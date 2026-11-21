/**
* @description MeshCentral-EventLog SQL configuration store (PostgreSQL / MariaDB / MySQL / SQLite). The plugin is live-only: no events are stored, only config sets and their assignments.
* @license Apache-2.0
*
* MeshCentral keeps its own connection for these engines private (only SQLite exposes db.file), so
* pg / MariaDB / MySQL get a small pool of their own built from the same meshcentral config, while
* SQLite shares MeshCentral's handle - opening a second handle on the same file would fight it for
* the write lock and miss its PRAGMA setup. Either way the tables live in MeshCentral's own
* database, so whatever backs it up covers them too.
*/

"use strict";

const T_SET = 'plugin_eventlog_settings';
const ASSIGN_CHUNK = 500;

// Connection settings, accepting both shapes MeshCentral accepts (a URL string or an object with
// an ssl block naming certificate files). MeshCentral defaults a missing database name to
// 'meshcentral' but applies it to a CLONE of the config (its db.js), so args still has no
// database - the caller must apply the same default or every query fails with "no database
// selected". Parsing never throws: this runs inside server_startup, which has no error handling.
function connConfig(raw) {
    if (raw == null) return {};
    if (typeof raw == 'string') {
        var c = {};
        try {
            var u = new URL(raw);
            c.host = decodeURIComponent(u.hostname);
            if (u.port) c.port = Number(u.port);
            if (u.username) c.user = decodeURIComponent(u.username);
            if (u.password) c.password = decodeURIComponent(u.password);
            var dbn = decodeURIComponent(String(u.pathname || '').replace(/^\//, ''));
            if (dbn != '') c.database = dbn;
        } catch (e) {
            // not a URL: fall back to how MeshCentral itself splits a connection string
            var parts = raw.split(/[:@/]+/);
            if (parts.length >= 5) { c.user = parts[1]; c.password = parts[2]; c.host = parts[3]; c.port = Number(parts[4]); if (parts[5]) c.database = parts[5]; }
            else { console.log('EVENTLOG: could not parse the database connection string'); }
        }
        return c;
    }
    var o = Object.assign({}, raw);
    if (o.ssl != null && typeof o.ssl == 'object') {
        var fs = require('fs'), ssl = {};
        try {
            if (o.ssl.cacertpath) ssl.ca = fs.readFileSync(o.ssl.cacertpath);
            if (o.ssl.clientcertpath) ssl.cert = fs.readFileSync(o.ssl.clientcertpath);
            if (o.ssl.clientkeypath) ssl.key = fs.readFileSync(o.ssl.clientkeypath);
        } catch (e) { console.log('EVENTLOG: could not read a TLS certificate file: ' + e.message); }
        if (o.ssl.dontcheckserveridentity === true) ssl.rejectUnauthorized = false;
        o.ssl = ssl;
    }
    return o;
}

function toNum(v) {
    if (v == null) return null;
    if (typeof v == 'bigint') return Number(v);          // mariadb/mysql BIGINT
    var n = Number(v);                                    // pg returns BIGINT and COUNT(*) as strings
    return isNaN(n) ? null : n;
}
function parseDoc(v) {
    if (v == null) return {};
    if (typeof v == 'string') { try { return JSON.parse(v); } catch (e) { return {}; } }
    if (Buffer.isBuffer(v)) { try { return JSON.parse(v.toString('utf8')); } catch (e) { return {}; } }
    return v;
}
function newId() { return require('crypto').randomBytes(12).toString('hex'); }

// install the SQL implementation onto the object CreateDB built (which already carries the
// backend-independent helpers from db.js)
module.exports.install = function (obj, meshserver, kind, shared) {
    var pool = null, sqlite = null, mysqlPool = null;
    var D = {};

    // ---- dialect ---------------------------------------------------------
    if (kind == 'pg') {
        var pg = shared.loadModule(['pg']);
        var pgcfg = Object.assign({}, connConfig(meshserver.args.postgres), { max: 3 });
        if (pgcfg.database == null) pgcfg.database = 'meshcentral';
        pool = new pg.Pool(pgcfg);
        // without this an idle connection error is an unhandled 'error' event and takes the server down
        pool.on('error', function (e) { console.log('EVENTLOG: postgres pool error: ' + (e.message || e)); });
        D.query = function (sql, params) {
            return pool.query(sql, params || []).then(function (r) { return { rows: r.rows || [], affected: r.rowCount || 0 }; });
        };
        D.ph = function (i) { return '$' + i; };
        D.like = 'ILIKE';
        D.jsonType = 'JSON';
        D.end = function () { return pool.end(); };
    } else if (kind == 'mariadb') {
        var mariadb = shared.loadModule(['mariadb']);
        var macfg = Object.assign({}, connConfig(meshserver.args.mariadb), {
            connectionLimit: 3, bigIntAsNumber: true, insertIdAsNumber: true, decimalAsNumber: true
        });
        if (macfg.database == null) macfg.database = 'meshcentral';   // same default MeshCentral applies
        pool = mariadb.createPool(macfg);
        D.query = function (sql, params) {
            return pool.query(sql, params || []).then(function (r) {
                if (Array.isArray(r)) return { rows: r, affected: r.length };
                return { rows: [], affected: toNum(r.affectedRows) || 0, insertId: toNum(r.insertId) };
            });
        };
        D.ph = function () { return '?'; };
        D.like = 'LIKE';
        D.jsonType = 'JSON';
        D.end = function () { return pool.end(); };
    } else if (kind == 'mysql') {
        var mysql2 = shared.loadModule(['mysql2']);
        var mycfg = Object.assign({}, connConfig(meshserver.args.mysql), {
            connectionLimit: 3, waitForConnections: true
        });
        if (mycfg.database == null) mycfg.database = 'meshcentral';   // same default MeshCentral applies
        mysqlPool = mysql2.createPool(mycfg);
        pool = mysqlPool.promise();
        D.query = function (sql, params) {
            // query(), not execute(): no prepared-statement cache to grow, and array params stay literal
            return pool.query(sql, params || []).then(function (res) {
                var r = res[0];
                if (Array.isArray(r)) return { rows: r, affected: r.length };
                return { rows: [], affected: toNum(r.affectedRows) || 0, insertId: toNum(r.insertId) };
            });
        };
        D.ph = function () { return '?'; };
        D.like = 'LIKE';
        D.jsonType = 'JSON';
        D.end = function () { return new Promise(function (res) { mysqlPool.end(function () { res(); }); }); };
    } else { // sqlite: share MeshCentral's handle
        sqlite = meshserver.db.file;
        D.query = function (sql, params) {
            return new Promise(function (resolve, reject) {
                if (/^\s*(SELECT|WITH|PRAGMA)/i.test(sql)) {
                    sqlite.all(sql, params || [], function (err, rows) {
                        if (err) reject(err); else resolve({ rows: rows || [], affected: (rows || []).length });
                    });
                } else {
                    sqlite.run(sql, params || [], function (err) {
                        if (err) reject(err); else resolve({ rows: [], affected: this.changes || 0, insertId: this.lastID });
                    });
                }
            });
        };
        D.ph = function () { return '?'; };
        D.like = 'LIKE';   // ASCII-only case folding, see the changelog
        D.jsonType = 'TEXT';
        D.end = function () { return Promise.resolve(); };   // not ours to close
    }
    var isMy = (kind == 'mysql' || kind == 'mariadb');

    // ---- schema ----------------------------------------------------------
    function ddl() {
        var stmts = [];
        if (isMy) {
            stmts.push('CREATE TABLE IF NOT EXISTS ' + T_SET + ' (' +
                'id VARCHAR(256) NOT NULL, type VARCHAR(32) NOT NULL, extra VARCHAR(256), doc JSON, ' +
                'PRIMARY KEY (id), INDEX ' + T_SET + '_type_extra (type, extra)' +
                ') CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci');
        } else {
            var vc = function (n) { return (kind == 'pg') ? ('VARCHAR(' + n + ')') : 'TEXT'; };
            stmts.push('CREATE TABLE IF NOT EXISTS ' + T_SET + ' (' +
                'id ' + vc(256) + ' PRIMARY KEY NOT NULL, type ' + vc(32) + ' NOT NULL, extra ' + vc(256) + ', doc ' + D.jsonType + ')');
            stmts.push('CREATE INDEX IF NOT EXISTS ' + T_SET + '_type_extra ON ' + T_SET + ' (type, extra)');
        }
        return stmts.reduce(function (p, s) { return p.then(function () { return D.query(s, []); }); }, Promise.resolve());
    }

    // ---- init / ready ----------------------------------------------------
    // Every public call goes through ready(). A failed init is retried rather than cached, and the
    // plugin never quietly falls back to its own files: that silent divergence is the bug this fixes.
    // ready() gates on the schema and the one-time import only. The steps that follow go through
    // the public API (checkForDefault -> getAllConfigSets -> ready()), so they must run after it
    // resolves, not inside it - awaiting the promise being built here would deadlock.
    function ready() {
        if (obj._ready != null) return obj._ready;
        obj._ready = ddl()
        .then(function () { return importFromNedb(); })
        .catch(function (e) {
            obj._ready = null;   // not cached: the retry below (or the next call) tries again
            obj._retry = Math.min((obj._retry || 30000) * 2, 900000);
            console.log('EVENTLOG: ' + kind + ' initialisation failed, retrying in ' + Math.round(obj._retry / 1000) + 's: ' + (e.message || e));
            // one pending retry at a time, so a long outage cannot pile up dead handles
            if (obj._retryTimer != null) { try { clearTimeout(obj._retryTimer); } catch (e3) { } }
            obj._retryTimer = setTimeout(function () { obj._retryTimer = null; bootstrap(); }, obj._retry);
            try { obj._retryTimer.unref(); } catch (e2) { }
            throw e;
        });
        return obj._ready;
    }

    function bootstrap() {
        obj.initialized = ready()
        .then(function () { return obj.checkForDefault(); })
        .then(function () {
            obj._retry = null;   // a later outage starts from the short backoff again
            console.log('EVENTLOG: ' + kind + ' storage ready');
        })
        .catch(function () { return null; });   // already logged; the retry timer takes it from here
        return obj.initialized;
    }
    // resolves when the backend is fully usable (schema, import, default config)
    obj.ready = function () { return obj.initialized; };

    // One-time carry-over of the plugin's own NeDB settings (config sets and their assignments).
    function importFromNedb() {
        return D.query('SELECT COUNT(*) AS n FROM ' + T_SET, []).then(function (r) {
            if ((toNum(r.rows[0] && r.rows[0].n) || 0) > 0) return null;
            var file;
            try { file = meshserver.getConfigFilePath('plugin-eventlog-settings.db'); } catch (e) { return null; }
            if (!require('fs').existsSync(file)) return null;
            var Datastore;
            try { Datastore = shared.loadModule(['@seald-io/nedb', '@yetzt/nedb', 'nedb']); } catch (e) { return null; }
            return new Promise(function (resolve) {
                var store = new Datastore({ filename: file, autoload: true });
                store.find({}, function (err, docs) {
                    if (err || docs == null || docs.length == 0) { resolve(null); return; }
                    var work = Promise.resolve(), n = 0;
                    docs.forEach(function (d) {
                        var id = null, extra = null, doc = Object.assign({}, d);
                        delete doc._id;
                        if (d.type == 'configSet') { id = String(d._id); extra = d.uid || null; }        // keep the id: assignments point at it
                        else if (d.type == 'assignedConfig') { id = 'assign:' + d.asset; extra = d.asset; }
                        else return;   // nodeMeta / db_version belonged to event storage and are not needed
                        n++;
                        work = work.then(function () { return putDoc(id, d.type, extra, doc); });
                    });
                    work.then(function () {
                        if (n > 0) console.log('EVENTLOG: imported ' + n + ' settings from the plugin NeDB file (the plugin-eventlog-*.db files are no longer used)');
                        resolve(null);
                    }).catch(function (e) { console.log('EVENTLOG: settings import failed: ' + (e.message || e)); resolve(null); });
                });
            });
        });
    }

    // ---- generic document helpers (settings table) -----------------------
    function putDoc(id, type, extra, doc) {
        var body = JSON.stringify(doc || {});   // always a string: pg would read a raw array as an array literal
        var p = [id, type, extra, body];
        var sql;
        if (isMy) {
            sql = 'INSERT INTO ' + T_SET + ' (id,type,extra,doc) VALUES (?,?,?,?) ' +
                  'ON DUPLICATE KEY UPDATE type=VALUES(type), extra=VALUES(extra), doc=VALUES(doc)';
        } else {
            sql = 'INSERT INTO ' + T_SET + ' (id,type,extra,doc) VALUES (' + D.ph(1) + ',' + D.ph(2) + ',' + D.ph(3) + ',' + D.ph(4) + ') ' +
                  'ON CONFLICT (id) DO UPDATE SET type=EXCLUDED.type, extra=EXCLUDED.extra, doc=EXCLUDED.doc';
        }
        return D.query(sql, p);
    }
    function rowToDoc(r) {
        var d = parseDoc(r.doc);
        d._id = r.id;
        return d;
    }
    function docsByType(type, extra) {
        var sql = 'SELECT id, doc FROM ' + T_SET + ' WHERE type = ' + D.ph(1);
        var p = [type];
        if (extra !== undefined) { sql += ' AND extra = ' + D.ph(2); p.push(extra); }
        return D.query(sql, p).then(function (r) { return r.rows.map(rowToDoc); });
    }
    function getDoc(id) {
        return D.query('SELECT id, doc FROM ' + T_SET + ' WHERE id = ' + D.ph(1), [id])
        .then(function (r) { return r.rows[0] ? rowToDoc(r.rows[0]) : null; });
    }

    // ---- config sets -----------------------------------------------------
    obj.getAllConfigSets = function () {
        return ready().then(function () { return docsByType('configSet'); });
    };
    obj.updateDefaultConfig = function (args) {
        return ready().then(function () { return docsByType('configSet'); })
        .then(function (list) {
            var cur = null;
            list.forEach(function (d) { if (d.default === true) cur = d; });
            var doc = Object.assign({}, cur || { default: true }, args);
            var id = (cur != null) ? cur._id : newId();
            delete doc._id;
            doc.type = 'configSet';
            doc.uid = Math.random().toString(32).replace('0.', '');   // invalidates the config the agents hold
            return putDoc(id, 'configSet', doc.uid, doc).then(function () { return { insertedId: id }; });
        });
    };
    obj.updateConfig = function (id, args) {
        return ready().then(function () { return (id == '_new') ? null : getDoc(id); })
        .then(function (cur) {
            var doc = Object.assign({}, cur || {}, args);
            delete doc._id;
            doc.type = 'configSet';
            doc.uid = Math.random().toString(32).replace('0.', '');
            var realId = (id == '_new' || cur == null) ? newId() : id;
            return putDoc(realId, 'configSet', doc.uid, doc).then(function () { return { insertedId: realId }; });
        });
    };
    obj.deleteConfigSet = function (id) {
        return ready().then(function () {
            return D.query('DELETE FROM ' + T_SET + ' WHERE id = ' + D.ph(1) + ' AND type = ' + D.ph(2), [id, 'configSet']);
        }).then(function (r) { return r.affected; });
    };
    obj.checkConfigAuth = function (uid) {
        return ready().then(function () {
            return D.query('SELECT COUNT(*) AS n FROM ' + T_SET + ' WHERE type = ' + D.ph(1) + ' AND extra = ' + D.ph(2), ['configSet', uid]);
        }).then(function (r) { return toNum(r.rows[0] && r.rows[0].n) || 0; });
    };
    obj.assignConfig = function (configId, sel) {
        if (configId == '') configId = 'default';
        sel = Array.isArray(sel) ? sel : [];
        return ready().then(function () {
            var chunks = [];
            for (var i = 0; i < sel.length; i += ASSIGN_CHUNK) chunks.push(sel.slice(i, i + ASSIGN_CHUNK));
            return chunks.reduce(function (p, c) {
                return p.then(function () {
                    var n = 2, ph = [];
                    c.forEach(function () { ph.push(D.ph(n++)); });
                    return D.query('DELETE FROM ' + T_SET + ' WHERE type = ' + D.ph(1) + ' AND extra IN (' + ph.join(',') + ')', ['assignedConfig'].concat(c));
                });
            }, Promise.resolve());
        })
        .then(function () {
            if (configId == '_clear') return null;   // clearing: the removal above is all there is to do
            return sel.reduce(function (p, asset) {
                return p.then(function () {
                    return putDoc('assign:' + asset, 'assignedConfig', asset, { type: 'assignedConfig', asset: asset, configId: configId });
                });
            }, Promise.resolve());
        })
        .catch(function (e) { console.log('EVENTLOG: Error assigning configs: ', e); });
    };
    obj.getConfigAssignments = function () {
        return ready().then(function () { return docsByType('assignedConfig'); })
        .then(function (docs) { return docs.map(function (d) { return { asset: d.asset, configId: d.configId }; }); });
    };

    obj._backendClose = function () {
        if (obj._retryTimer != null) { try { clearTimeout(obj._retryTimer); } catch (e) { } obj._retryTimer = null; }
        try { D.end(); } catch (e) { }
    };

    bootstrap();
    return obj;
};
