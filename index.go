package main

import (
    "github.com/go-redis/redis"
	"log"
)

func main() {
    client := redis.NewClient(&redis.Options{
        Addr:     "localhost:6379",
        Password: "", // no password set
        DB:       0,  // use default DB
    })

    // Ping Redis to check if the connection is working
    // res, err := client.Ping().Result()
	err := client.Set("key", "Uday", 0).Err()
    if err != nil {
        panic(err)
    }	
	res,err:=client.Get("key").Result()
	log.Println(res)
	log.Println("Connected to Redis")

}