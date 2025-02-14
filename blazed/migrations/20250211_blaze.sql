-- Account tables
CREATE TABLE IF NOT EXISTS Users(
    id   INTEGER NOT NULL PRIMARY KEY,
    name TEXT    NOT NULL,
    hash TEXT    NOT NULL,
    salt TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS UserAllowedIPs(
    id INTEGER NOT NULL,
    ip TEXT    NOT NULL,
    PRIMARY KEY (id, ip),
    FOREIGN KEY (id) REFERENCES Users(id)
);

CREATE TABLE IF NOT EXISTS UserAllowedTokens(
    id    INTEGER NOT NULL,
    token TEXT    NOT NULL,
    PRIMARY KEY (id, token),
    FOREIGN KEY (id) REFERENCES Users(id)
);

-- Host / network tables
CREATE TABLE IF NOT EXISTS Networks(
    -- An IPv4 or IPv6 with a mask.
    cidr              TEXT    NOT NULL PRIMARY KEY,
    short_timeout_ms  INTEGER NOT NULL DEFAULT 500,
    long_timeout_ms   INTEGER NOT NULL DEFAULT 15000,
    linux_root_user   TEXT    NOT NULL DEFAULT "root",
    windows_root_user TEXT    NOT NULL DEFAULT "Administrator",
    default_pass      TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS NetworkIgnoredHosts(
    cidr TEXT NOT NULL,
    ip   TEXT NOT NULL,
    PRIMARY KEY (cidr, ip),
    FOREIGN KEY (cidr) REFERENCES Networks(cidr) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS Hosts(
    -- The network the host belongs to.
    cidr TEXT NOT NULL,
    -- An IPv4 or IPv6.
    ip   TEXT NOT NULL,
    -- Optional - overrides network config
    user TEXT,
    -- Optional - overrides network config
    pass TEXT,
    -- One of Windows or UnixLike
    os   TEXT NOT NULL,
    PRIMARY KEY (cidr, ip),
    FOREIGN KEY (cidr) REFERENCES Networks(cidr) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS HostAliases(
    cidr  TEXT NOT NULL,
    ip    TEXT NOT NULL,
    alias TEXT NOT NULL,
    PRIMARY KEY (cidr, ip, alias),
    FOREIGN KEY (cidr, ip) REFERENCES Hosts(cidr, ip) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS HostPorts(
    cidr TEXT     NOT NULL,
    ip   TEXT     NOT NULL,
    port SMALLINT NOT NULL,
    PRIMARY KEY (cidr, ip, port),
    FOREIGN KEY (cidr, ip) REFERENCES Hosts(cidr, ip) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS HostLogs(
    cidr  TEXT     NOT NULL,
    ip    TEXT     NOT NULL,
    -- Time when the log was generated
    stamp DATETIME NOT NULL,
    line  TEXT     NOT NULL,
    PRIMARY KEY (cidr, ip, stamp),
    FOREIGN KEY (cidr, ip) REFERENCES Host(cidr, ip) ON DELETE CASCADE
);

-- Service tables
CREATE TABLE IF NOT EXISTS Services(
    name TEXT NOT NULL PRIMARY KEY,
    -- Information about the service
    info TEXT NOT NULL,
    -- The type of service it is
    type TEXT NOT NULL,
    cidr TEXT,
    ip   TEXT,
    FOREIGN KEY (cidr, ip) REFERENCES Hosts(cidr, ip) ON DELETE CASCADE
);

-- Password tables
CREATE TABLE IF NOT EXISTS Passwords(
    round    INTEGER NOT NULL,
    id       INTEGER NOT NULL,
    password TEXT    NOT NULL,
    -- One of 'windows', 'linux', 'misc'
    type     TEXT    NOT NULL,
    PRIMARY KEY (round, id)
);

CREATE TABLE IF NOT EXISTS PasswordUsages(
    round INTEGER NOT NULL,
    id    INTEGER NOT NULL,
    -- Description of what it's used for
    info  TEXT    NOT NULL,
    FOREIGN KEY (round, id) REFERENCES Passwords(round, id)
);

CREATE TABLE IF NOT EXISTS PasswordUsageByHost(
    round     INTEGER NOT NULL,
    id        INTEGER NOT NULL,
    host_cidr TEXT    NOT NULL,
    host_ip   TEXT    NOT NULL,
    FOREIGN KEY (round, id) REFERENCES Passwords(round, id),
    FOREIGN KEY (host_cidr, host_ip) REFERENCES Hosts(cidr, ip)
);

CREATE TABLE IF NOT EXISTS PasswordUsageByService(
    round   INTEGER NOT NULL,
    id      INTEGER NOT NULL,
    service TEXT    NOT NULL,
    FOREIGN KEY (round, id) REFERENCES Passwords(round, id),
    FOREIGN KEY (service) REFERENCES Services(name)
);
