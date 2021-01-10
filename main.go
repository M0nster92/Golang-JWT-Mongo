package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

var (
	MongoURI   = flag.String("mongouri", "mongodb+srv://sami_92:sami_92@cluster0.dovo5.mongodb.net/?retryWrites=true&w=majority", "test_database")
	collection = flag.String("CRUD Database", "maxcrm", " for example")
	DBClient   *mongo.Client
	AppDB      *mongo.Database
)

type User struct {
	Username     string `json:"username"`
	FirstName    string `json:"firstname"`
	LastName     string `json:"lastname"`
	Password     string `json:"password"`
	Token        string `json:"token, omitempty"`
	TokenExpired int64  `json:"tokenexpired, omitempty"`
}

type ResponseResult struct {
	Error  string      `json:"error, omitempty"`
	Status string      `json:"status, omitempty"`
	Data   interface{} `json:"data, omitempty"`
}

type ResponseUser struct {
	Expires      time.Time `json:"expires"`
	SessionToken string    `json:"sessionID"`
	UserInfo     UserInfo  `json:"userInfo"`
}

type UserInfo struct {
	DisplayName string   `json:"displayName"`
	Groups      []string `json:"groups"`
	Username    string   `json:"username"`
}

func init() {
	flag.Parse()
	DBClient = DBConnect(*MongoURI)
	if DBClient != nil {
		AppDB = DBClient.Database(*collection)
	}
}

func main() {
	r := mux.NewRouter()
	r.Methods("OPTIONS").HandlerFunc(HandleOptions)
	r.HandleFunc("/", Hello).Methods("GET")
	r.HandleFunc("/register", Register).Methods("POST")
	r.HandleFunc("/login", Login).Methods("POST")
	r.HandleFunc("/auth/{token}", Auth).Methods("GET")
	r.HandleFunc("/kill/{username}", DeleteSession).Methods("GET")

	log.Info("Server start at port 8080")
	log.Fatal(http.ListenAndServe(":8080", r))

}

func HandleOptions(w http.ResponseWriter, r *http.Request) {
	CORSHeaders(w, r)
}

func CORSHeaders(w http.ResponseWriter, r *http.Request) {
	headers := w.Header()
	log.Infof("Request Origin is: %v", r.Header.Get("Origin"))
	headers.Add("Access-Control-Allow-Origin", "*")
	headers.Add("Access-Control-Allow-Headers", "Content-Type, Origin, Accept, token, api-key")
	headers.Add("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	headers.Add("Access-Control-Max-Age", "3600")
}

func DBConnect(URI string) *mongo.Client {
	clientOptions := options.Client().ApplyURI(URI)
	client, err := mongo.Connect(context.TODO(), clientOptions)
	if err != nil {
		log.Infof("Problem connecting MongoURI %v, error : %v ", URI, err)
	}

	err = client.Ping(context.TODO(), nil)
	if err != nil {
		log.Infof("Problem pinging server %v, err %v", URI, err)
	} else {
		log.Infof("Connected to Mongodb server %v", URI)
	}

	return client
}

func Hello(w http.ResponseWriter, r *http.Request) {
	CORSHeaders(w, r)
	fmt.Fprintf(w, "Homepage")
}

func Register(w http.ResponseWriter, r *http.Request) {
	CORSHeaders(w, r)
	//w.Header().Set("Content-Type", "application/json")
	var user User
	body, _ := ioutil.ReadAll(r.Body)
	err := json.Unmarshal(body, &user)
	fmt.Println(user, err)
	var res ResponseResult
	if err != nil {
		res.Error = err.Error()
		json.NewEncoder(w).Encode(res)
		return
	}

	collection := AppDB.Collection("crmuser")
	var resultUser User
	cur := collection.FindOne(context.TODO(), bson.D{{"username", user.Username}}).Decode(&resultUser)
	if resultUser.Username == "" {
		log.Infof("No Documents found %v", cur)
		hash, err := bcrypt.GenerateFromPassword([]byte(user.Password), 5)

		if err != nil {
			res.Error = " Error while hashing password"
			json.NewEncoder(w).Encode(res)
			return
		}

		user.Password = string(hash)

		insert, err := collection.InsertOne(context.TODO(), user)
		if err != nil {
			res.Error = "Error while Creating User, try again"
			json.NewEncoder(w).Encode(res)
			return
		}

		res.Status = "ok"
		res.Data = insert
		json.NewEncoder(w).Encode(res)
		return

	}

	res.Error = "Username alreeady Taken"
	json.NewEncoder(w).Encode(res)
	return
}

func Login(w http.ResponseWriter, r *http.Request) {
	CORSHeaders(w, r)
	//w.Header().Set("Content-Type", "application/json")
	var user User
	body, _ := ioutil.ReadAll(r.Body)
	err := json.Unmarshal(body, &user)
	if err != nil {
		log.Info(err)
	}

	collection := AppDB.Collection("crmuser")
	var resultUser User
	var res ResponseResult

	err = collection.FindOne(context.TODO(), bson.D{{"username", user.Username}}).Decode(&resultUser)
	if err != nil {
		res.Error = "Invalid Username"
		json.NewEncoder(w).Encode(res)
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(resultUser.Password), []byte(user.Password))
	if err != nil {
		res.Error = "Invalid Username"
		json.NewEncoder(w).Encode(res)
		return
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username":  resultUser.Username,
		"firstname": resultUser.FirstName,
		"lastname":  resultUser.LastName,
	})

	tokenString, err := token.SignedString([]byte("secret"))
	if err != nil {
		res.Error = "Error while generating Token, Try Again"
		json.NewEncoder(w).Encode(res)
		return
	}

	resultUser.Token = tokenString
	addOneHour := time.Now().Add(1 * time.Hour)
	resultUser.TokenExpired = addOneHour.Unix()
	up, err := collection.UpdateOne(context.TODO(), bson.M{"username": resultUser.Username}, bson.D{{Key: "$set", Value: resultUser}})
	if err != nil {
		res.Error = "Error extending new session"
		json.NewEncoder(w).Encode(res)
		return
	}
	log.Info("Profile Modified ", up.ModifiedCount)

	var responseUser ResponseUser

	responseUser.Expires = addOneHour
	responseUser.SessionToken = tokenString

	responseUser.UserInfo = UserInfo{
		DisplayName: resultUser.Username,
		Username:    resultUser.Username,
	}

	res.Status = "ok"
	res.Data = responseUser
	json.NewEncoder(w).Encode(res)
	return

}

func Auth(w http.ResponseWriter, r *http.Request) {
	CORSHeaders(w, r)
	//w.Header().Set("Content-Type", "application/json")
	var response ResponseResult
	var user User
	token := mux.Vars(r)["token"]

	collection := AppDB.Collection("crmuser")
	cur := collection.FindOne(context.TODO(), bson.M{"token": token}).Decode(&user)
	if cur != nil {
		log.Info("User not Found")
		response.Data = "User not Found"
		json.NewEncoder(w).Encode(response)
		return
	}

	log.Info("Token Found")

	//normalTime := time.Unix(user.TokenExpired, 0)
	addOneHour := time.Now().Add(1 * time.Hour)
	user.TokenExpired = addOneHour.Unix()

	up, err := collection.UpdateOne(context.TODO(),
		bson.M{"token": token},
		bson.D{{Key: "$set", Value: user}})
	if err != nil {
		log.Info("Error extending Session")
		response.Data = "User not Found"
		json.NewEncoder(w).Encode(response)
		return
	}

	log.Info("Session Extended ", up.ModifiedCount)
	var responseUser ResponseUser

	responseUser.Expires = time.Unix(user.TokenExpired, 0)
	responseUser.SessionToken = user.Token

	responseUser.UserInfo = UserInfo{
		DisplayName: user.Username,
		Username:    user.Username,
	}

	response.Status = "ok"
	response.Data = responseUser
	json.NewEncoder(w).Encode(response)
	return
}

func DeleteSession(w http.ResponseWriter, r *http.Request) {
	CORSHeaders(w, r)
	var response ResponseResult
	username := mux.Vars(r)["username"]
	collection := AppDB.Collection("crmuser")
	delete := collection.FindOneAndUpdate(context.TODO(),
		bson.M{"username": username},
		bson.D{
			{"$set", bson.D{{"token", ""}}},
		},
	)
	if delete == nil {
		log.Info("Error deleting Token")
		response.Error = "Error deleting Token"
		json.NewEncoder(w).Encode(response)
		return
	}

	response.Status = "ok"
	json.NewEncoder(w).Encode(response)
	return

}
