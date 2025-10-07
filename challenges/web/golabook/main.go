package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/talgarr/serialize/cmd/api"
	"github.com/talgarr/serialize/cmd/database"
)

func main() {
	db, err := database.NewDb()
	if err != nil {
		log.Fatalln(fmt.Errorf("error while creating database: %w", err))
	}

	path := os.Getenv("INITIAL_BOOK_PATH")
	file, err := os.ReadFile(path)
	if err != nil {
		log.Fatalln(fmt.Errorf("error while reading INITIAL_BOOK_PATH %s: %w", path, err))
	}

	api := api.Api{
		Db:          db,
		Dev:         false,
		Flag:        os.Getenv("FLAG"),
		CurrentBook: string(file),
	}

	http.HandleFunc("/api/register", api.Register)
	http.HandleFunc("/api/login", api.Login)
	http.HandleFunc("/api/logout", api.Logout)
	http.HandleFunc("/api/upload_config", api.UploadConfig)
	http.HandleFunc("/api/read_book", api.ReadBook)
	http.HandleFunc("/api/write_book", api.WriteBook)

	fmt.Println("Listening on 0.0.0.0:8080")
	log.Fatalln(http.ListenAndServe(":8080", nil))
}
