package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

type UserClaims struct {
	UserId    int `json:"userId"`
	SessionId int `json:"sessionId"`
	jwt.StandardClaims
}

var (
	secret = []byte{}
)

func main() {
	secret = []byte("secret-de-prueba")

	mux := http.NewServeMux()
	mux.HandleFunc("/getToken", getToken)
	mux.HandleFunc("/validateToken", validateToken)
	http.ListenAndServe(":80", mux)
}

func getToken(w http.ResponseWriter, r *http.Request) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, UserClaims{1019, 1145, jwt.StandardClaims{ExpiresAt: time.Now().Add(2 * time.Hour).Unix(), Issuer: "demo"}})

	signedToken, err := token.SignedString(secret)
	if err != nil {
		fmt.Printf("getToken: %s", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		b, _ := json.Marshal(map[string]interface{}{
			"message": "couldn't generate the signed token",
		})
		w.Write(b)
		return
	}

	fmt.Println(signedToken)

	w.WriteHeader(http.StatusInternalServerError)
	b, _ := json.Marshal(map[string]interface{}{
		"token": signedToken,
	})

	w.Write(b)
}

func validateToken(w http.ResponseWriter, r *http.Request) {
	params := struct {
		Token string `json:"token"`
	}{}

	err := json.NewDecoder(r.Body).Decode(&params)
	if err != nil {
		fmt.Printf("validateToken: decoder: %s\n", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		b, _ := json.Marshal(map[string]interface{}{
			"message": "error parsing parameters",
		})

		w.Write(b)
		return
	}

	fmt.Println(params.Token)

	token, err := jwt.Parse(params.Token, func(t *jwt.Token) (interface{}, error) {
		_, ok := t.Method.(*jwt.SigningMethodHMAC)
		if !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}

		return secret, nil
	})

	if err != nil {
		fmt.Printf("validateToken: parsing: %s", err.Error())
		w.WriteHeader(http.StatusNotAcceptable)
		b, _ := json.Marshal(map[string]interface{}{
			"message": "error validating token",
		})

		w.Write(b)
		return
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		fmt.Printf("validateToken: claims: %s", err.Error())
		w.WriteHeader(http.StatusNotAcceptable)
		b, _ := json.Marshal(map[string]interface{}{
			"message": "invalid token",
		})

		w.Write(b)
		return
	}

	fmt.Printf("user:%v, session:%v", claims["userId"], claims["sessionId"])

	b, _ := json.Marshal(map[string]interface{}{
		"message": "your token is valid",
	})

	w.Write(b)
}
