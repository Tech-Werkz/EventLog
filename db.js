/**
* @description MeshCentral-EventLog database module
* @author Ryan Blenis
* @copyright Ryan Blenis 2019
* @license Apache-2.0
*
* The plugin is live-only: it does NOT store any events. This module only keeps the plugin's
* configuration - the config sets edited in the plugin admin page and their node / mesh assignments.
*/

"use strict";
var Datastore = null;

// MeshCentral uses this same value for every one of its own NeDB stores. Compaction rewrites the
// WHOLE datafile synchronously on the event loop, so a short interval would stall the server.
const COMPACTION_INTERVAL_MS = 24 * 60 * 60 * 1000;

// Resolve a module from the plugin folder first, then from MeshCentral's own node_modules
// (plugins live in meshcentral-data/plugins, which is not always below MeshCentral's node_modules).
function loadModule(names) {
    var lastErr = null;
    for (var i in names) {
        try { return require(names[i]); } catch (e) { lastErr = e; }
        try { if (require.main && typeof require.main.require == 'function') return require.main.require(names[i]); } catch (e) { lastErr = e; }
    }
    throw lastErr || new Error('Module not found: ' + names.join(', '));
}

// ---- shared helpers (backend independent, also used by db_sql.js) --------

// config-set resolution, identical for every backend
function installShared(obj) {
    obj.getConfigFor = function(nodeId, meshId) {
        // Every step is chained (not fire-and-forget) so that a backend failure rejects this promise
        // instead of leaving it pending forever with an unhandled rejection behind it.
        return obj.getConfigAssignments()
        .then(function (ca) {
            var configId = 'default';
            (ca || []).forEach(function (a) { if (a.asset == meshId) configId = a.configId; });
            (ca || []).forEach(function (a) { if (a.asset == nodeId) configId = a.configId; });
            return configId;
        })
        .then(function (configId) {
            return obj.getAllConfigSets().then(function (sets) {
                var configBlob = null;
                (sets || []).forEach(function (s) {
                    if (configId == 'default' && s.default === true) configBlob = s;
                    else if (s._id == configId) configBlob = s;
                });
                return configBlob;
            });
        });
    };

    obj.checkForDefault = function() {
        return obj.getAllConfigSets()
        .then((cfgs) => {
            if (cfgs.length == 0) {
                return obj.updateDefaultConfig({
                    name: 'Default',
                    liveLogs: 'Application,System',
                    liveNum: 100,
                    liveEntryTypes: [2,3],
                    liveCategories: [],          // Linux journald categories; empty = no filter
                    liveCategoriesMode: 'exclude',
                    liveSources: '',             // source / provider names, '*' wildcards; empty = no filter
                    liveSourcesMode: 'exclude'
                });
            }
        })
        .catch(function () { });
    };
}

module.exports.CreateDB = function(meshserver) {
    // server_startup runs again when a plugin is installed or reloaded (pluginHandler.js). Without
    // this, every reload leaks another store.
    try {
        var prev = (meshserver.pluginHandler != null) ? meshserver.pluginHandler.eventlog_db : null;
        if (prev != null && typeof prev.close == 'function') { prev.close(); console.log('EVENTLOG: closed previous database instance'); }
    } catch (e) { }

    var obj = {};
    obj._closed = false;
    installShared(obj);

    obj.close = function() {
        obj._closed = true;
        if (obj.settingsFile != null) {
            try {
                var f = obj.settingsFile;
                if (typeof f.stopAutocompaction == 'function') f.stopAutocompaction();
                else if (f.persistence != null && typeof f.persistence.stopAutocompaction == 'function') f.persistence.stopAutocompaction();
            } catch (e) { }
        }
        if (obj.mongoClient != null) { try { obj.mongoClient.close(); } catch (e) { } obj.mongoClient = null; }
        if (typeof obj._backendClose == 'function') { try { obj._backendClose(); } catch (e) { } }
    };

    // Which store do we use? databaseType comes from MeshCentral itself (db.js):
    // 1 NeDB, 2 MongoJS, 3 MongoDB, 4 MariaDB, 5 MySQL, 6 PostgreSQL, 7 AceBase, 8 SQLite.
    var sqlKind = null;
    if (String(process.env.EVENTLOG_STORAGE || '').toLowerCase() != 'nedb') {
        var dt = 0;
        try { dt = (meshserver.db != null && meshserver.db.databaseType != null) ? Number(meshserver.db.databaseType) : 0; } catch (e) { }
        if (dt == 6) sqlKind = 'pg';
        else if (dt == 4) sqlKind = 'mariadb';
        else if (dt == 5) sqlKind = 'mysql';
        else if (dt == 8) {
            // SQLite is the one engine whose handle MeshCentral exposes; sharing it avoids fighting
            // the same file for the write lock and inherits MeshCentral's PRAGMA setup.
            if (meshserver.db.file != null && typeof meshserver.db.file.all == 'function') sqlKind = 'sqlite';
            else console.log('EVENTLOG: MeshCentral is on SQLite but its database handle is not usable here - using NeDB files instead');
        }
    }
    if (sqlKind != null) {
        console.log('EVENTLOG: config storage backend = ' + sqlKind + ' (MeshCentral database); events are not stored');
        require(__dirname + '/db_sql.js').install(obj, meshserver, sqlKind, { loadModule: loadModule });
        return obj;
    }

    if (meshserver.args.mongodb) { // use MongDB
      console.log('EVENTLOG: config storage backend = mongodb; events are not stored');
      loadModule(['mongodb']).MongoClient.connect(meshserver.args.mongodb, { useNewUrlParser: true, useUnifiedTopology: true }, function (err, client) {
          if (err != null) { console.log("Unable to connect to database: " + err); process.exit(); return; }
          obj.mongoClient = client;

          var dbname = 'meshcentral';
          if (meshserver.args.mongodbname) { dbname = meshserver.args.mongodbname; }
          const db = client.db(dbname);

          obj.settingsFile = db.collection('plugin_eventlog_settings');

          obj.updateDefaultConfig = function(args) {
              args.type = 'configSet';
              args.uid = Math.random().toString(32).replace('0.', '');
              return obj.settingsFile.updateOne({default: true}, { $set: args }, {upsert: true});
          };
          obj.updateConfig = function(id, args) {
              if (args._id != null) delete args._id;
              args.type = "configSet";
              args.uid = Math.random().toString(32).replace('0.', '');
              if (id == '_new') return obj.settingsFile.insertOne(args);
              var mdb = loadModule(['mongodb']);
              id = (typeof mdb.ObjectID == 'function') ? mdb.ObjectID(id) : new mdb.ObjectId(id);
              return obj.settingsFile.updateOne({_id: id}, { $set: args }, {upsert: true});
          };
          obj.getAllConfigSets = function() {
              return obj.settingsFile.find({type: "configSet"}).project({type: 0}).toArray();
          };
          obj.deleteConfigSet = function(id) {
              var mdb = loadModule(['mongodb']);
              id = (typeof mdb.ObjectID == 'function') ? mdb.ObjectID(id) : new mdb.ObjectId(id);
              return obj.settingsFile.deleteOne({_id: id});
          };
          obj.assignConfig = function(configId, sel) {
              if (configId == '') configId = "default";
              // multiple selections may not update, we need to delete and insert here
              return obj.settingsFile.deleteMany({type: "assignedConfig", asset: { $in: sel } })
              .then(() => {
                  if (configId == '_clear') { return; }
                  var inserts = [];
                  sel.forEach((s) => {
                      inserts.push({
                        type: "assignedConfig",
                        asset: s,
                        configId: configId
                      });
                  });
                  return obj.settingsFile.insertMany(inserts);
              })
              .catch((e) => console.log("EVENTLOG: Error assigning configs: ", e));
          }
          obj.getConfigAssignments = function() {
              return obj.settingsFile.find( { type: "assignedConfig" } ).project( { _id: 0, asset: 1, configId: 1 } ).toArray();
          }
          obj.checkConfigAuth = function(uid) {
            return obj.settingsFile.countDocuments( { type: "configSet", uid: uid } );
          }

          obj.checkForDefault();
    });
    } else { // use NeDb
        console.log('EVENTLOG: config storage backend = nedb (plugin-private file); events are not stored');
        Datastore = loadModule(['@seald-io/nedb', '@yetzt/nedb', 'nedb']); // same fallback order as MeshCentral itself
        if (obj.settingsFile == null) {
            obj.settingsFile = new Datastore({ filename: meshserver.getConfigFilePath('plugin-eventlog-settings.db'), autoload: true });
            if (typeof obj.settingsFile.setAutocompactionInterval == 'function') obj.settingsFile.setAutocompactionInterval(COMPACTION_INTERVAL_MS);
            else obj.settingsFile.persistence.setAutocompactionInterval(COMPACTION_INTERVAL_MS);
        }

        obj.updateDefaultConfig = function(args) {
            args.type = 'configSet';
            args.uid = Math.random().toString(32).replace('0.', '');
            // NeDB's classic update() returns undefined, not a promise - wrap it so callers can .then()
            return new Promise(function(resolve, reject) {
                obj.settingsFile.update({default: true}, { $set: args }, {upsert: true}, function(err, numAffected) {
                    if (err) reject(err); else resolve(numAffected);
                });
            });
        };
        obj.updateConfig = function(id, args) {
            return new Promise(function(resolve, reject) {
                if (args._id != null) delete args._id;
                args.type = "configSet";
                args.uid = Math.random().toString(32).replace('0.', '');
                if (id == '_new') {
                    obj.settingsFile.insert(args, function(err, newDocs) {
                        if (err) { reject(err); return; }
                        newDocs.insertedId = newDocs._id;
                        resolve(newDocs);
                    });
                } else {
                    obj.settingsFile.update({_id: id}, { $set: args }, {upsert: true, returnUpdatedDocs: true}, function(err, numDocs, upDocs) {
                        if (err) { reject(err); return; }
                        upDocs.insertedId = upDocs._id;
                        resolve(upDocs);
                    });
                }
            });
        };
        obj.getAllConfigSets = function(callback) {
            return new Promise(function(resolve, reject) {
                obj.settingsFile.find({type: "configSet"}).exec((err, sets) => {
                  if (err) { reject(err); return; }
                  resolve(sets);
                });
            });
        };
        obj.deleteConfigSet = function(id) {
            return new Promise(function(resolve, reject) {
                obj.settingsFile.remove({_id: id}, (err, numRemoved) => {
                    if (err) { reject(err); return; }
                    resolve(numRemoved);
                });
            });
        };
        obj.assignConfig = function(configId, sel) {
            return new Promise(function(resolve, reject) {
                if (configId == '') configId = "default";
                // multiple selections may not update, we need to delete and insert here
                obj.settingsFile.remove({type: "assignedConfig", asset: { $in: sel } }, { multi: true }, () => {
                      if (configId == '_clear') { resolve(); return; } // clearing: the removal above is all there is to do
                      var inserts = [];
                      sel.forEach((s) => {
                          inserts.push({
                            type: "assignedConfig",
                            asset: s,
                            configId: configId
                          });
                      });
                      obj.settingsFile.insert(inserts, () => resolve());
                  }
                )
            });
        }
        obj.getConfigAssignments = function(callback) {
            return new Promise(function(resolve, reject) {
                obj.settingsFile.find( { type: "assignedConfig" }, { _id: 0, asset: 1, configId: 1 } ).exec((err, docs) => {
                  resolve(docs || []);
                });
            });
        }
        obj.checkConfigAuth = function(uid) {
          return new Promise(function(resolve, reject) {
              obj.settingsFile.count( { type: "configSet", uid: uid } , function(err, count){
                  resolve(count);
              });
          });
        }

        obj.checkForDefault();
    }

    return obj;
};
