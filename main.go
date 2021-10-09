package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/postgres"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"
)

//---------------------------GLOBAL VARIABLES----------------
var (
	router    *mux.Router
	secretkey string = "secretkeyjwt"
)

//---------------------------STRUCTS------------------------
type User struct {
	gorm.Model
	Name     string `json:"name"`
	Email    string `gorm:"unique" json:"email"`
	Password string `json:"password"`
	Role     string `json:"role"`
}

type Authentication struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type Token struct {
	Role        string `json:"role"`
	Email       string `json:"email"`
	TokenString string `json:"token"`
}

type Error struct {
	IsError bool   `json:"isError"`
	Message string `json:"message"`
}

//-----------------------------DATABASE FUNCTIONS--------------------

// returns database connection
func GetDatabase() *gorm.DB {
	err := godotenv.Load()
	if err != nil {
		log.Fatalln("Error loading .env file")
	}
	databaseUrl := os.Getenv("DATABASE_URL")
	database := "postgres"
	connection, err := gorm.Open(database, databaseUrl)
	if err != nil {
		log.Fatalln("wrong database url")
	}
	sqldb := connection.DB()
	err = sqldb.Ping()
	if err != nil {
		log.Fatalln("database connection error")
	}
	fmt.Println("connected to database")
	return connection
}

// create user table in userdb
func InitialMigration() {
	connection := GetDatabase()
	defer Closeddatabase(connection)
	connection.AutoMigrate(User{})
}

// close database connection
func Closeddatabase(connection *gorm.DB) {
	sqldb := connection.DB()
	sqldb.Close()
}

//---------------------------HELPER FUNCTIONS------------------

//set error message in Error struct
func SetError(err Error, message string) Error {
	err.IsError = true
	err.Message = message
	return err
}

// take password as input and generate new hash password from it
func GenerateHashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

// compare plain password with hash password
func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// Generate JWT token
func GenerateJWT(email, role string) (string, error) {
	var mySigninKey = []byte(secretkey)
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)

	claims["authorized"] = true
	claims["email"] = email
	claims["role"] = role
	claims["exp"] = time.Now().Add(time.Minute * 30).Unix()

	tokenString, err := token.SignedString(mySigninKey)

	if err != nil {
		fmt.Errorf("Something Went Wrong: %s", err.Error())
		return "", err
	}
	return tokenString, nil
}

//---------------------MIDDLEWARE FUNCTION----------------

// check whether user is authorized or not
func IsAuthorized(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Header["Token"] == nil {
			var err Error
			err = SetError(err, "No Token Found")
			json.NewEncoder(w).Encode(err)
			return
		}
		var mySigninKey = []byte(secretkey)

		token, err := jwt.Parse(r.Header["Token"][0], func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("There was an error in parsing")
			}
			return mySigninKey, nil
		})

		if err != nil {
			var err Error
			err = SetError(err, "Your Token has been expired")
			json.NewEncoder(w).Encode(err)
			return
		}

		if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			if claims["role"] == "admin" {
				r.Header.Set("Role", "admin")
				handler.ServeHTTP(w, r)
				return
			} else if claims["role"] == "user" {
				r.Header.Set("Role", "user")
				handler.ServeHTTP(w, r)
				return
			}
		}
		var reserr Error
		reserr = SetError(reserr, "Not Authrorized")
		json.NewEncoder(w).Encode(err)
	}
}

//------------------------ROUTES----------------------

// create a mux router
func CreateRouter() {
	router = mux.NewRouter()
}

// initialize all routes
func InitializeRoute() {
	router.HandleFunc("/signup", SignUp).Methods("POST")
	router.HandleFunc("/signin", SignIn).Methods("POST")
	router.HandleFunc("/admin", IsAuthorized(AdminIndex)).Methods("GET")
	router.HandleFunc("/user", IsAuthorized(UserIndex)).Methods("GET")
	router.HandleFunc("/", Index).Methods("GET")
	router.Methods("OPTIONS").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Acess-Control-Allow-Origin", "")
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
		w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, x-CSRF-Token, Authorization, Access-Control-Request-Headers, Access-Control-Request-Method, Connection, Host, Origin, User-Agent, Refer, Cache-Control, X-header")
	})
}

// start the server
func ServerStart() {
	fmt.Println("Server started at http://localhost:8080...")
	headers := handlers.AllowedHeaders(
		[]string{"X-Requested-With", "Access-Control-Allow-Origin", "Content-Type", "Authorization"})
	methods := handlers.AllowedMethods([]string{"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"})
	origin := handlers.AllowedOrigins([]string{"*"})
	err := http.ListenAndServe(":8080", handlers.CORS(headers, methods, origin)(router))
	if err != nil {
		log.Fatal(err)
	}
}

//-------------------------ROUTES HANDLER---------------------

func SignUp(w http.ResponseWriter, r *http.Request) {
	connection := GetDatabase()
	defer Closeddatabase(connection)

	var user User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		var err Error
		err = SetError(err, "Error in reading body")
		w.Header().Set("Content-type", "application/json")
		json.NewEncoder(w).Encode(err)
		return
	}
	var dbuser User
	connection.Where("email = ?", user.Email).First(&dbuser)

	if dbuser.Email != "" {
		var err Error
		err = SetError(err, "Email already in use")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(err)
		return
	}
	user.Password, err = GenerateHashPassword(user.Password)
	if err != nil {
		log.Fatalln("error in password hash")
	}

	connection.Create(&user)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(user)
}

func SignIn(w http.ResponseWriter, r *http.Request) {
	connection := GetDatabase()
	defer Closeddatabase(connection)

	var authdetails Authentication
	err := json.NewDecoder(r.Body).Decode(&authdetails)
	if err != nil {
		var err Error
		err = SetError(err, "Error in reading body")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(err)
		return
	}
	var authuser User
	connection.Where("email = ?", authdetails.Email).First(&authuser)
	if authuser.Email == "" {
		var err Error
		err = SetError(err, "Username or Password is incorrect")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(err)
		return
	}

	check := CheckPasswordHash(authdetails.Password, authuser.Password)
	if !check {
		var err Error
		err = SetError(err, "Username or Password is incorrect")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(err)
		return
	}

	validToken, err := GenerateJWT(authuser.Email, authuser.Role)
	if err != nil {
		var err Error
		err = SetError(err, "Failed to generate token")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(err)
		return
	}

	var token Token
	token.Email = authuser.Email
	token.Role = authuser.Role
	token.TokenString = validToken
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(token)
}

func Index(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("HOME PUBLIC INDEX PAGE"))
}

func AdminIndex(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Role") != "admin" {
		w.Write([]byte("Not authorized"))
		return
	}
	w.Write([]byte("Welcome, Admin."))
}

func UserIndex(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Role") != "user" {
		w.Write([]byte("Not Authorized"))
		return
	}
	w.Write([]byte("Welcome, User."))
}

func main() {
	InitialMigration()
	CreateRouter()
	InitializeRoute()
	ServerStart()
}
