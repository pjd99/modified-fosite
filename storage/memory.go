package storage

import (
	"time"
	"github.com/ory-am/fosite"
	"github.com/pkg/errors"
	"golang.org/x/net/context"
	"database/sql"
	_ "github.com/go-sql-driver/mysql"
	"fmt"
	"log"
)

// Global sql.DB to access the database by all handlers
var db *sql.DB 
var err error

type MemoryUserRelation struct {
	Username string
	Password string
}

type MemoryStore struct {
	Clients        map[string]*fosite.DefaultClient
	AuthorizeCodes map[string]fosite.Requester
	IDSessions     map[string]fosite.Requester
	AccessTokens   map[string]fosite.Requester
	Implicit       map[string]fosite.Requester
	RefreshTokens  map[string]fosite.Requester
	Users          map[string]MemoryUserRelation
	// In-memory request ID to token signatures
	AccessTokenRequestIDs  map[string]string
	RefreshTokenRequestIDs map[string]string
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		Clients:        make(map[string]*fosite.DefaultClient),
		AuthorizeCodes: make(map[string]fosite.Requester),
		IDSessions:     make(map[string]fosite.Requester),
		AccessTokens:   make(map[string]fosite.Requester),
		Implicit:       make(map[string]fosite.Requester),
		RefreshTokens:  make(map[string]fosite.Requester),
		Users:          make(map[string]MemoryUserRelation),
		AccessTokenRequestIDs:  make(map[string]string),
		RefreshTokenRequestIDs: make(map[string]string),
	}
}

func NewExampleStore() *MemoryStore {
	return &MemoryStore{
		IDSessions: make(map[string]fosite.Requester),
		Clients: map[string]*fosite.DefaultClient{
			"my-client": {
				ID:            "my-client",
				// Secret:        []byte(`$2a$10$IxMdI6d.LIRZPpSfEwNoeu4rY3FhDREsxFJXikcgdRRAStxUlsuEO`), // = "foobar"
				RedirectURIs:  []string{"http://localhost:3846/callback"},
				ResponseTypes: []string{"id_token", "code", "token"},
				GrantTypes:    []string{"implicit", "refresh_token", "authorization_code", "password", "client_credentials"},
				Scopes:        []string{"fosite", "openid", "photos", "offline"},
				Public:        true,
			},
			 "ttnctl": {
                                ID:            "ttnctl",
                                // Secret:        []byte(`$2a$10$IxMdI6d.LIRZPpSfEwNoeu4rY3FhDREsxFJXikcgdRRAStxUlsuEO`), // = "foobar"
                                RedirectURIs:  []string{"http://localhost:3846/callback"},
                                ResponseTypes: []string{"id_token", "code", "token"},
                                GrantTypes:    []string{"implicit", "refresh_token", "authorization_code", "password", "client_credentials"},
                                Scopes:        []string{"fosite", "openid", "photos", "offline"},
				Public:        true,
                        },
		},
		Users: map[string]MemoryUserRelation{
			"pauldoherty@rfproximity.com": {
				// This store simply checks for equality, a real storage implementation would obviously use
				// a hashing algorithm for encrypting the user password.
				Username: "pauldoherty@rfproximity.com",
				Password: "smellyhead1",
			},
		},
		AuthorizeCodes:         map[string]fosite.Requester{},
		Implicit:               map[string]fosite.Requester{},
		AccessTokens:           map[string]fosite.Requester{},
		RefreshTokens:          map[string]fosite.Requester{},
		AccessTokenRequestIDs:  map[string]string{},
		RefreshTokenRequestIDs: map[string]string{},
	}
}

func GetDatabase() *sql.DB {
	if db != nil {
		return db
	}
	var err error
	if err = Retry(time.Second*15, time.Minute*2, func() error {
	    fmt.Printf("Connecting to MySQL DB")

	    db, err = sql.Open("mysql", "pjd99:oxford13@/ess_auth_server")
	    if err != nil {
	        fmt.Printf("Could not connect to MySQl: %s", err)    
	    }else if err := db.Ping(); err != nil {
		fmt.Printf("Could not connect to MySQL: %s", err)
	    }

	    fmt.Printf("Connected to MySQL!")
	    return nil
	}); err != nil {
		panic(err.Error())
	}

	return db
}


func Retry(maxWait time.Duration, failAfter time.Duration, f func() error) (err error) {
	var lastStart time.Time
	err = errors.New("Did not connect.")
	loopWait := time.Millisecond * 100
	retryStart := time.Now()
	for retryStart.Add(failAfter).After(time.Now()) {
		lastStart = time.Now()
		if err = f(); err == nil {
			return nil
		}

		if lastStart.Add(maxWait * 2).Before(time.Now()) {
			retryStart = time.Now()
		}
		fmt.Printf("Error, Retrying connection in %f seconds...", loopWait.Seconds())
		time.Sleep(loopWait)
		loopWait = loopWait * time.Duration(int64(2))
		if loopWait > maxWait {
			loopWait = maxWait
		}
	}
	return err
}

func LoadStore() *MemoryStore {
        /****
	 // Create an sql.DB and check for errors
        db, err = sql.Open("mysql", "pjd99:oxford13@/ess_auth_server")
        if err != nil {
                panic(err.Error())    
        }
        // sql.DB should be long lived "defer" closes it once this function ends
        defer db.Close()

	// Test the connection to the database
        err = db.Ping()
        if err != nil {
                panic(err.Error())
        }
	***/

	var dbcon *sql.DB = GetDatabase()
        // Grab from the database 

	var (
		email string
		password string
	)

	rows, err := dbcon.Query("SELECT email, password FROM users")
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()

	allUsers := make(map[string]MemoryUserRelation)

	for rows.Next() {
		err := rows.Scan(&email, &password)
		if err != nil {
			log.Fatal(err)
		}
		userRow := MemoryUserRelation{Username: email, Password: password}
		allUsers[email] = userRow 
		fmt.Printf("email: %s and password: %s", email, password)
	}
	err = rows.Err()
	if err != nil {
		log.Fatal(err)
	}

        return &MemoryStore{
                IDSessions: make(map[string]fosite.Requester),
                Clients: map[string]*fosite.DefaultClient{
                        "my-client": {
                                ID:            "my-client",
                                // Secret:        []byte(`$2a$10$IxMdI6d.LIRZPpSfEwNoeu4rY3FhDREsxFJXikcgdRRAStxUlsuEO`), // = "foobar"
                                RedirectURIs:  []string{"http://localhost:3846/callback"},
                                ResponseTypes: []string{"id_token", "code", "token"},
                                GrantTypes:    []string{"implicit", "refresh_token", "authorization_code", "password", "client_credentials"},
                                Scopes:        []string{"fosite", "openid", "photos", "offline"},
                                Public:        true,
                        },
                         "ttnctl": {
                                ID:            "ttnctl",
                                // Secret:        []byte(`$2a$10$IxMdI6d.LIRZPpSfEwNoeu4rY3FhDREsxFJXikcgdRRAStxUlsuEO`), // = "foobar"
                                RedirectURIs:  []string{"http://localhost:3846/callback"},
                                ResponseTypes: []string{"id_token", "code", "token"},
                                GrantTypes:    []string{"implicit", "refresh_token", "authorization_code", "password", "client_credentials"},
                                Scopes:        []string{"fosite", "openid", "photos", "offline"},
                                Public:        true,
                        },
                },
                Users: allUsers,

                AuthorizeCodes:         map[string]fosite.Requester{},
                Implicit:               map[string]fosite.Requester{},
                AccessTokens:           map[string]fosite.Requester{},
                RefreshTokens:          map[string]fosite.Requester{},
                AccessTokenRequestIDs:  map[string]string{},
                RefreshTokenRequestIDs: map[string]string{},
        }
}



func (s *MemoryStore) DataBaseTest() error {
	// Create an sql.DB and check for errors
    	db, err = sql.Open("mysql", "pjd99:oxford13@/ess_auth_server")
    	if err != nil {
        	panic(err.Error())    
    	}
   	 // sql.DB should be long lived "defer" closes it once this function ends
    	defer db.Close()

    	// Test the connection to the database
    	err = db.Ping()
    	if err != nil {
        	panic(err.Error())
    	}
    	// Grab from the database 
    	username := "pjd99"
    	var databaseUsername  string
    	var databasePassword  string
    	err := db.QueryRow("SELECT user_name, password FROM users WHERE user_name=?", username).Scan(&databaseUsername, &databasePassword)
  
   	if err == nil {
        	fmt.Printf("username: %s and password: %s", databaseUsername, databasePassword)
        	return nil
    	}        
        return nil
}

func (s *MemoryStore) CreateOpenIDConnectSession(_ context.Context, authorizeCode string, requester fosite.Requester) error {
	s.IDSessions[authorizeCode] = requester
	return nil
}

func (s *MemoryStore) GetOpenIDConnectSession(_ context.Context, authorizeCode string, requester fosite.Requester) (fosite.Requester, error) {
	cl, ok := s.IDSessions[authorizeCode]
	if !ok {
		return nil, fosite.ErrNotFound
	}
	return cl, nil
}

func (s *MemoryStore) DeleteOpenIDConnectSession(_ context.Context, authorizeCode string) error {
	delete(s.IDSessions, authorizeCode)
	return nil
}

func (s *MemoryStore) GetClient(id string) (fosite.Client, error) {
	cl, ok := s.Clients[id]
	if !ok {
		return nil, fosite.ErrNotFound
	}
	return cl, nil
}

func (s *MemoryStore) CreateAuthorizeCodeSession(_ context.Context, code string, req fosite.Requester) error {
	s.AuthorizeCodes[code] = req
	return nil
}

func (s *MemoryStore) GetAuthorizeCodeSession(_ context.Context, code string, _ fosite.Session) (fosite.Requester, error) {
	rel, ok := s.AuthorizeCodes[code]
	if !ok {
		return nil, fosite.ErrNotFound
	}
	return rel, nil
}

func (s *MemoryStore) DeleteAuthorizeCodeSession(_ context.Context, code string) error {
	delete(s.AuthorizeCodes, code)
	return nil
}

func (s *MemoryStore) CreateAccessTokenSession(_ context.Context, signature string, req fosite.Requester) error {
	s.AccessTokens[signature] = req
	s.AccessTokenRequestIDs[req.GetID()] = signature
	return nil
}

func (s *MemoryStore) GetAccessTokenSession(_ context.Context, signature string, _ fosite.Session) (fosite.Requester, error) {
	rel, ok := s.AccessTokens[signature]
	if !ok {
		return nil, fosite.ErrNotFound
	}
	return rel, nil
}

func (s *MemoryStore) DeleteAccessTokenSession(_ context.Context, signature string) error {
	delete(s.AccessTokens, signature)
	return nil
}

func (s *MemoryStore) CreateRefreshTokenSession(_ context.Context, signature string, req fosite.Requester) error {
	s.RefreshTokens[signature] = req
	s.RefreshTokenRequestIDs[req.GetID()] = signature
	return nil
}

func (s *MemoryStore) GetRefreshTokenSession(_ context.Context, signature string, _ fosite.Session) (fosite.Requester, error) {
	rel, ok := s.RefreshTokens[signature]
	if !ok {
		return nil, fosite.ErrNotFound
	}
	return rel, nil
}

func (s *MemoryStore) DeleteRefreshTokenSession(_ context.Context, signature string) error {
	delete(s.RefreshTokens, signature)
	return nil
}

func (s *MemoryStore) CreateImplicitAccessTokenSession(_ context.Context, code string, req fosite.Requester) error {
	s.Implicit[code] = req
	return nil
}

func (s *MemoryStore) Authenticate(_ context.Context, name string, secret string) error {
	rel, ok := s.Users[name]
	if !ok {
		return fosite.ErrNotFound
	}
	if rel.Password != secret {
		return errors.New("Invalid credentials")
	}
	return nil
}

func (s *MemoryStore) ReloadUsers(name string, secret string) error {
	
	var dbcon *sql.DB = GetDatabase()
        // Grab from the database 

	var (
		email string
		password string
	)

	rows, err := dbcon.Query("SELECT email, password FROM users")
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()

	allUsers := make(map[string]MemoryUserRelation)

	for rows.Next() {
		err := rows.Scan(&email, &password)
		if err != nil {
			log.Fatal(err)
		}
		userRow := MemoryUserRelation{Username: email, Password: password}
		allUsers[email] = userRow 
		fmt.Printf("email: %s and password: %s", email, password)
	}
	err = rows.Err()
	if err != nil {
		log.Fatal(err)
	}
	
	s.Users = allUsers
	
	rel, ok := s.Users[name]
	if !ok {
		return errors.New("Credentials not found")
	}
	if rel.Password != secret {
		return errors.New("Credentials not found")
	}
	return nil
}

func (s *MemoryStore) PersistAuthorizeCodeGrantSession(ctx context.Context, authorizeCode, accessSignature, refreshSignature string, request fosite.Requester) error {
	if err := s.DeleteAuthorizeCodeSession(ctx, authorizeCode); err != nil {
		return err
	} else if err := s.CreateAccessTokenSession(ctx, accessSignature, request); err != nil {
		return err
	} else if refreshSignature == "" {
		return nil
	} else if err := s.CreateRefreshTokenSession(ctx, refreshSignature, request); err != nil {
		return err
	}

	return nil
}
func (s *MemoryStore) PersistRefreshTokenGrantSession(ctx context.Context, originalRefreshSignature, accessSignature, refreshSignature string, request fosite.Requester) error {
	if err := s.DeleteRefreshTokenSession(ctx, originalRefreshSignature); err != nil {
		return err
	} else if err := s.CreateAccessTokenSession(ctx, accessSignature, request); err != nil {
		return err
	} else if err := s.CreateRefreshTokenSession(ctx, refreshSignature, request); err != nil {
		return err
	}

	return nil
}
func (s *MemoryStore) RevokeRefreshToken(ctx context.Context, requestID string) error {
	if signature, exists := s.RefreshTokenRequestIDs[requestID]; exists {
		s.DeleteRefreshTokenSession(ctx, signature)
	}
	return nil
}

func (s *MemoryStore) RevokeAccessToken(ctx context.Context, requestID string) error {
	if signature, exists := s.AccessTokenRequestIDs[requestID]; exists {
		s.DeleteAccessTokenSession(ctx, signature)
	}
	return nil
}
