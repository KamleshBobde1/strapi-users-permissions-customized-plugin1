const sqlite = {
  client: 'sqlite',
  connection: {
    filename: '.tmp/data.db',
  },
  useNullAsDefault: true,
};

const postgres = {
  client: 'postgres',
  connection: {
    database: 'strapi_db',
    user: 'postgres',
    password: 'postgres',
    port: 5432,
    host: 'localhost',
  },
};

const mysql = {
  client: 'mysql',
  connection: {
    database: 'strapi',
    user: 'strapi',
    password: 'strapi',
    port: 3306,
    host: 'localhost',
  },
};

const db = {
  mysql,
  sqlite,
  postgres,
};

module.exports = {
  connection: process.env.DB ? db[process.env.DB] || db.sqlite : db.sqlite,
};
