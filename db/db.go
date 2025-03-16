package db

import (
	"database/sql"
	_ "github.com/mattn/go-sqlite3"
)

func InitDB() (*sql.DB, error) {
	db, err := sql.Open("sqlite3", "users.db")
	if err != nil {
		return nil, err
	}

	// 创建用户表
	_, err = db.Exec(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            display_name TEXT,
            avatar_url TEXT,
            web_authn_credentials TEXT
        )
    `)
	if err != nil {
		return nil, err
	}

	// 新增：创建 OAuth2.0 客户端信息表
	_, err = db.Exec(`
        CREATE TABLE IF NOT EXISTS oauth2_clients (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            client_id TEXT UNIQUE NOT NULL,
            client_secret TEXT NOT NULL,
            redirect_uri TEXT NOT NULL,
            domain TEXT
        )
    `)
	if err != nil {
		return nil, err
	}

	return db, nil
}
