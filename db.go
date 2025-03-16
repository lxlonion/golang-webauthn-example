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
	if err != nil {
		return nil, err
	}

	//创建订单表 order表中的sale和buyer字段用username,time用unix时间戳
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS orders (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			seller TEXT,
			buyer TEXT,
			price INTEGER NOT NULL,
			post_link TEXT NOT NULL,
			time INTEGER NOT NULL, -- unix时间戳
			status TEXT DEFAULT 'A' -- 订单状态：A-没有发货(默认)，B-已经发货，C-确定签收
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
