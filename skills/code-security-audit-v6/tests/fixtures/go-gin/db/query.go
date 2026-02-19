package db

import (
	"database/sql"
	"fmt"
)

var DB *sql.DB

func ExecuteQuery(query string, args ...interface{}) (*sql.Rows, error) {
	return DB.Query(query, args...)
}

func UnsafeQuery(userInput string) (sql.Result, error) {
	query := fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", userInput)
	return DB.Exec(query)
}
