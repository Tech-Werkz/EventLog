# MeshCentral-EventLog

*Current Version: 2.0.0
Released: 2026-11-21*

Initially conceived as a proof of concept plugin for the [MeshCentral2](https://github.com/Ylianst/MeshCentral) Project to introduce extensibility into the project without requiring the MeshCentral2 project to incorporate everyone's requested changes into the main project, yet allow it to be accomplished by others. In creating this plugin, we're introducing the appropriate hooks into MeshCentral2 to allow extensibility to anyone who can write a plugin, while trying to modify the core project as little as possible.

## Installation

 Pre-requisite: First, make sure you have plugins enabled for your MeshCentral installation:
>     "plugins": {
>          "enabled": true
>     },
Restart your MeshCentral server after making this change.

 To install, simply add the plugin configuration URL when prompted:
 `https://raw.githubusercontent.com/v3DJG6GL/MeshCentral-EventLog/master/config.json`

Once installed, you'll need to update your agent cores (restart the agent) so the live view uses the new agent module.

## Usage
*Live only: events are read from the device while the tab is open and are never stored. Supports Windows endpoints (Windows Event Log via PowerShell) and Linux endpoints (systemd-journald via journalctl) with a software agent installed. On Linux, events are shown in KSystemLog-style categories (System, Application, Kernel, Auth, Cron, Daemon, Audit); endpoints without systemd (e.g. Alpine, OpenWRT) are detected and flat-file /var/log support is planned.*

As a proof of concept, several methods were employed to become familiar with the [MeshCentral2](https://github.com/Ylianst/MeshCentral) project. 

#### Permissions
Access to the Event Log tab is controlled with MeshCentral's plugin permissions. In MeshCentral's permissions dialog (global, device group or device level) grant **Event Log: Live Tab**. It is denied by default, so only the users you allow can use the plugin, and they also need MeshCentral rights on the device. Without the permission the live tunnel is not opened. The plugin admin page is limited to MeshCentral administrators.

Live is opened by the browser through MeshCentral's own relay tunnel, so its permission is enforced by the tab; a user who also has MeshCentral's console rights on a device can still run `plugin eventlog getlog` there.

#### Plugin Admin
You can create configuration sets and assign them to nodes or meshes. Each set filters what the Live view shows, each with an Include/Exclude switch:
- **Logs** - Windows event logs (`Application,System,Security`)
- **Categories (Linux)** - journald categories: System, Application, Kernel, Auth, Cron, Daemon, Audit. *Application* is program output and is usually the noisy one on desktops
- **Sources** - source / provider names, comma-delimited, `*` wildcards (e.g. exclude `plasmashell, kwin*`). Works on both OSes
- **Entry Types** - levels; on Linux they map onto syslog priorities (Critical 0-2, Error 3, Warning 4, Info 5-6, Verbose 7)
- **Default entries** - how many entries per log the Live view asks for initially

#### Endpoint - Plugin tab
When viewing a remote endpoint, a new "Event Log" tab appears under the Plugins tab. It follows MeshCentral's light and night themes and uses the full width of the window.

- **Live** pulls the latest N entries (10-500, selectable on the tab; the admin config set provides the default) of the configured logs and entry types straight from the device, refreshes automatically every 30 s and can be paused. It only runs while the tab is on screen.
- **Filters**: level chips with counts, Log, Source (application/service name), Event ID lists and ranges (`1112, 100-199`), time range and free-text search. Click a column header to sort.
- **Layouts**: *Table* (dense, expandable rows) or *Viewer* (facet sidebar with counts, list and a details pane with the full message and raw JSON). *Fold repeats* collapses identical events into one line with an x N badge.
- **Sizing**: drag a column header's right edge to resize it (double-click fits the column to its content), drag the rail under the table (Table) or between list and details (Viewer) to change the height, drag the rail next to the Viewer sidebar to change its width, and pick a row density (*Rows*: Compact / Normal / Wrap). All of it is remembered per browser; a *Reset* link in the status line restores the defaults.
- **Export** the filtered rows as CSV.

#### Endpoint - Console tab
You can see the application logs directly from the console, using the command:

> plugin eventlog getlog

This will, by default, get the latest 10 Application Log errors and warnings.
Advanced usages can specify in greater detail, e.g.

> plugin eventlog getlog System 100 Error false

Let's break that down:

`plugin` informs the system that you are about to utilize a plugin call

`eventlog` calls this eventlog module

`System` references the requested event log set

`100` is the number of entries to be returned

`Error` is the type of event log (e.g. Error, Information, Warning, etc.)

`false` is whether or not to return JSON formatted output, rather than truncated text

 
## Storage

The plugin does **not store events**. The only thing it saves is its configuration (config sets and their assignments), in MeshCentral's own database so it is covered by the same backup:

| MeshCentral database | Where the config is stored |
| --- | --- |
| MongoDB | `plugin_eventlog_settings` collection |
| PostgreSQL, MariaDB, MySQL, SQLite | `plugin_eventlog_settings` table |
| NeDB (the default for small installs) | `plugin-eventlog-settings.db` in `meshcentral-data` |

The startup log says which one is in use (`EVENTLOG: config storage backend = ...`). Setting the environment variable `EVENTLOG_STORAGE=nedb` keeps the config in the plugin's own file.

Upgrading from a version that collected events: the old event collection / table / `plugin-eventlog-events.db` is no longer used and is not deleted automatically; drop it yourself if you want the space back (see the changelog).

# Future

This project may be expanded to include:
- Thoughts welcome- please feel free to suggest something that might be useful to you

# Screenshots
![Device Plugin Page](https://user-images.githubusercontent.com/1929277/67437370-adcd1200-f5be-11e9-9750-99f9c89b4c11.png)
![Plugin Administration Page](https://user-images.githubusercontent.com/1929277/69597525-4565bc00-0fd4-11ea-8722-55fe06ed64cd.png)