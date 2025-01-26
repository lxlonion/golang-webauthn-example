package main

import (
	"database/sql"
	"encoding/json"

	"github.com/go-webauthn/webauthn/webauthn"
	_ "github.com/mattn/go-sqlite3"
)

func initDB() (*sql.DB, error) {
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
	return db, err
}

// 将凭证转换为JSON字符串
func credentialsToJSON(creds []webauthn.Credential) (string, error) {
	if len(creds) == 0 {
		return "[]", nil
	}
	data, err := json.Marshal(creds)
	return string(data), err
}

// 将JSON字符串转换回凭证数组
func credentialsFromJSON(data string) ([]webauthn.Credential, error) {
	var creds []webauthn.Credential
	if err := json.Unmarshal([]byte(data), &creds); err != nil {
		return nil, err
	}
	return creds, nil
}
