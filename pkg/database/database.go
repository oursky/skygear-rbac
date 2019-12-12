package database

import (
	"database/sql"
	"log"
	"time"
)

// OpenDB opens a connection to database
func OpenDB(databaseURL string, retryCount int) (*sql.DB, error) {
	db, err := func() (*sql.DB, error) {
		var err error
		for i := 0; i < retryCount; i++ {
			dbb, errr := sql.Open("postgres", databaseURL)
			if errr == nil {
				return dbb, nil
			}
			err = errr
			log.Println("🔌 RBAC failed to connect db, retrying...")
			time.Sleep(time.Second)
		}
		return nil, err
	}()
	return db, err
}
