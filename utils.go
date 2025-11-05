/*
Copyright (C) 2025 github.com/go-schwab

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, see
<https://www.gnu.org/licenses/>.
*/

package trader

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/bytedance/sonic"
	o "github.com/go-schwab/utils/oauth"
	"golang.org/x/oauth2"
)

type Agent struct {
	Client       *o.AuthorizedClient
	Tokens       Token
	appkey       string
	secret       string
	callback_url string
	token_path   string
}

type Token struct {
	RefreshExpiration time.Time
	Refresh           string
	BearerExpiration  time.Time
	Bearer            string
}

type Option func(*Agent)

func WithAppKey(appkey string) Option {
	return func(a *Agent) {
		a.appkey = appkey
	}
}

func WithSecret(secret string) Option {
	return func(a *Agent) {
		a.secret = secret
	}
}

func WithCallbackUrl(url string) Option {
	return func(a *Agent) {
		a.callback_url = url
	}
}

func WithTokenPath(token_path string) Option {
	return func(a *Agent) {
		a.token_path = token_path
	}
}

var (
	APPKEY string
	SECRET string
	CBURL  string
	PATH   string
)

// load env variables, check if you've run the program before
func init() {
	homedir, err := os.UserHomeDir()
	isErrNil(err)
	PATH = homedir + "/.config/go-schwab/token.json"
	if _, err := os.Stat(homedir + "/.config/go-schwab"); errors.Is(err, os.ErrNotExist) {
		err := os.Mkdir(homedir+"/.config/go-schwab", 0750)
		isErrNil(err)
	}
}

// trim one FIRST & one LAST character in the string
func trimOneFirstOneLast(s string) string {
	if len(s) < 1 {
		return ""
	}
	return s[1 : len(s)-1]
}

// parse access token response
func parseAccessTokenResponse(s string) Token {
	token := Token{
		RefreshExpiration: time.Now().Add(time.Hour * 168),
		BearerExpiration:  time.Now().Add(time.Minute * 30),
	}
	for _, x := range strings.Split(s, ",") {
		for i1, x1 := range strings.Split(x, ":") {
			if trimOneFirstOneLast(x1) == "refresh_token" {
				token.Refresh = trimOneFirstOneLast(strings.Split(x, ":")[i1+1])
			} else if trimOneFirstOneLast(x1) == "access_token" {
				token.Bearer = trimOneFirstOneLast(strings.Split(x, ":")[i1+1])
			}
		}
	}
	return token
}

// Credit: https://gist.github.com/hyg/9c4afcd91fe24316cbf0
func openBrowser(url string) {
	var err error
	switch runtime.GOOS {
	case "linux":
		err = exec.Command("xdg-open", url).Start()
	case "windows":
		err = exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	case "darwin":
		err = exec.Command("open", url).Start()
	default:
		log.Fatal("Unsupported platform.")
	}
	isErrNil(err)
}

// Credit: https://go.dev/play/p/C2sZRYC15XN
func getStringInBetween(str string, start string, end string) (result string) {
	s := strings.Index(str, start)
	if s == -1 {
		return
	}
	s += len(start)
	e := strings.Index(str[s:], end)
	if e == -1 {
		return
	}
	return str[s : s+e]
}

// read in tokens from PATH - linux
func readLinuxDB() Token {
	var tokens Token
	body, err := os.ReadFile(PATH)
	isErrNil(err)
	err = sonic.Unmarshal(body, &tokens)
	isErrNil(err)
	return tokens
}

// read in tokens from PATH - mac & windows
func readDB() Agent {
	var tok *oauth2.Token
	body, err := os.ReadFile(PATH)
	isErrNil(err)
	err = sonic.Unmarshal(body, &tok)
	isErrNil(err)
	conf := &oauth2.Config{
		ClientID:     APPKEY, // Schwab App Key
		ClientSecret: SECRET, // Schwab App Secret
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://api.schwabapi.com/v1/oauth/authorize",
			TokenURL: "https://api.schwabapi.com/v1/oauth/token",
		},
	}
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{},
	}
	sslcli := &http.Client{Transport: tr}
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, sslcli)
	return Agent{
		Client: &o.AuthorizedClient{
			conf.Client(ctx, tok),
			tok,
		},
	}
}

// create Agent - linux
func initiateLinux() Agent {
	var agent Agent
	// oAuth Leg 1 - Authorization Code
	openBrowser(fmt.Sprintf("https://api.schwabapi.com/v1/oauth/authorize?client_id=%s&redirect_uri=%s", os.Getenv("APPKEY"), os.Getenv("CBURL")))
	fmt.Printf("Log into your Schwab brokerage account. Copy Error404 URL and paste it here: ")
	var urlInput string
	fmt.Scanln(&urlInput)
	authCodeEncoded := getStringInBetween(urlInput, "?code=", "&session=")
	authCode, err := url.QueryUnescape(authCodeEncoded)
	isErrNil(err)
	// oAuth Leg 2 - Refresh, Bearer Tokens
	authStringLegTwo := fmt.Sprintf("Basic %s", base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", os.Getenv("APPKEY"), os.Getenv("SECRET")))))
	client := http.Client{}
	payload := fmt.Sprintf("grant_type=authorization_code&code=%s&redirect_uri=%s", string(authCode), os.Getenv("CBURL"))
	req, err := http.NewRequest("POST", "https://api.schwabapi.com/v1/oauth/token", bytes.NewBuffer([]byte(payload)))
	isErrNil(err)
	req.Header = http.Header{
		"Authorization": {authStringLegTwo},
		"Content-Type":  {"application/x-www-form-urlencoded"},
	}
	res, err := client.Do(req)
	isErrNil(err)
	defer res.Body.Close()
	bodyBytes, err := io.ReadAll(res.Body)
	isErrNil(err)
	agent.Tokens = parseAccessTokenResponse(string(bodyBytes))
	bytes, err := sonic.Marshal(agent.Tokens)
	isErrNil(err)
	err = os.WriteFile(PATH, bytes, 0750)
	isErrNil(err)
	return agent
}

func initiateMacWindows() Agent {
	var agent Agent
	agent = Agent{Client: o.Initiate(APPKEY, SECRET, CBURL)}
	bytes, err := sonic.Marshal(agent.Client.Token)
	isErrNil(err)
	err = os.WriteFile(PATH, bytes, 0750)
	isErrNil(err)
	return agent
}

func NewAgent(options ...Option) *Agent {
	var agent Agent
	for _, option := range options {
		option(&agent)
	}

	// Deal with legacy
	APPKEY = agent.appkey
	SECRET = agent.secret
	CBURL = agent.callback_url

	if _, err := os.Stat(PATH); errors.Is(err, os.ErrNotExist) {
		agent.Client = o.Initiate(agent.appkey, agent.secret, agent.callback_url)
		bytes, err := sonic.Marshal(agent.Client.Token)
		if err != nil {
			log.Fatalf("Error unmarshalling client token: %v", err)
		}
		err = os.WriteFile(PATH, bytes, 0750)
		if err != nil {
			log.Fatalf("Error writing client token to %s: %v", PATH, err)
		}
	} else {
		var tok *oauth2.Token
		body, err := os.ReadFile(PATH)
		isErrNil(err)
		err = sonic.Unmarshal(body, &tok)
		isErrNil(err)
		conf := &oauth2.Config{
			ClientID:     agent.appkey, // Schwab App Key
			ClientSecret: agent.secret, // Schwab App Secret
			Endpoint: oauth2.Endpoint{
				AuthURL:  "https://api.schwabapi.com/v1/oauth/authorize",
				TokenURL: "https://api.schwabapi.com/v1/oauth/token",
			},
		}
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{},
		}
		sslcli := &http.Client{Transport: tr}
		ctx := context.WithValue(context.Background(), oauth2.HTTPClient, sslcli)
		agent.Client = &o.AuthorizedClient{
			conf.Client(ctx, tok),
			tok,
		}
	}

	return &agent
}

// create Agent - mac & windows
func Initiate() *Agent {
	var agent Agent
	if runtime.GOOS == "linux" {
		if _, err := os.Stat(PATH); errors.Is(err, os.ErrNotExist) {
			agent = initiateLinux()
		} else {
			agent.Tokens = readLinuxDB()
		}
	} else {
		if _, err := os.Stat(PATH); errors.Is(err, os.ErrNotExist) {
			agent = initiateMacWindows()
		} else {
			agent = readDB()
		}
	}
	return &agent
}

func Reinitiate() *Agent {
	var agent Agent
	if _, err := os.Stat(PATH); !errors.Is(err, os.ErrNotExist) {
		err := os.Remove(PATH)
		isErrNil(err)
	}
	if runtime.GOOS == "linux" {
		agent = initiateLinux()
	} else {
		agent = initiateMacWindows()
	}
	return &agent
}

// use refresh to generate a new bearer token for authentication
func (agent *Agent) Refresh() {
	oldTokens := readLinuxDB()
	authStringRefresh := fmt.Sprintf("Basic %s", base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", os.Getenv("APPKEY"), os.Getenv("SECRET")))))
	client := http.Client{}
	req, err := http.NewRequest("POST", "https://api.schwabapi.com/v1/oauth/token", bytes.NewBuffer([]byte(fmt.Sprintf("grant_type=refresh_token&refresh_token=%s", oldTokens.Refresh))))
	isErrNil(err)
	req.Header = http.Header{
		"Authorization": {authStringRefresh},
		"Content-Type":  {"application/x-www-form-urlencoded"},
	}
	res, err := client.Do(req)
	isErrNil(err)
	defer res.Body.Close()
	bodyBytes, err := io.ReadAll(res.Body)
	isErrNil(err)
	agent.Tokens = parseAccessTokenResponse(string(bodyBytes))
}

// Handler is the general purpose request function for the td-ameritrade api, all functions will be routed through this handler function, which does all of the API calling work
// It performs a GET request after adding the apikey found in the config.env file in the same directory as the program calling the function,
// then returns the body of the GET request's return.
// It takes one parameter:
// req = a request of type *http.Request
func (agent *Agent) Handler(req *http.Request) (*http.Response, error) {
	var (
		resp *http.Response
		err  error
	)
	if runtime.GOOS == "linux" {
		if !time.Now().Before(agent.Tokens.BearerExpiration) {
			agent.Refresh()
		}
		req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", agent.Tokens.Bearer))
		client := http.Client{}
		resp, err = client.Do(req)
		if err != nil {
			agent = Reinitiate()
		}
	} else {
		resp, err = agent.Client.Do(req)
		if err != nil {
			agent = Reinitiate()
		}
	}

	if resp == nil {
		log.Fatalf("Response in handler was nil")
	}

	switch resp.StatusCode {
	case http.StatusOK, http.StatusCreated:
		return resp, nil
	case http.StatusUnauthorized:
		body, err := io.ReadAll(resp.Body)
		isErrNil(err)
		if strings.Contains(string(body), "\"status\": 500") {
			return nil, WrapTraderError(ErrUnexpectedServer, resp)
		}
		return nil, WrapTraderError(ErrNeedReAuthorization, resp)
	case http.StatusForbidden:
		return nil, WrapTraderError(ErrForbidden, resp)
	case http.StatusNotFound:
		return nil, WrapTraderError(ErrNotFound, resp)
	case http.StatusInternalServerError:
		return nil, WrapTraderError(ErrUnexpectedServer, resp)
	case http.StatusServiceUnavailable:
		return nil, WrapTraderError(ErrTemporaryServer, resp)
	case http.StatusBadRequest:
		body, err := io.ReadAll(resp.Body)
		isErrNil(err)
		if strings.Contains(string(body), "\"status\": 500") {
			return nil, WrapTraderError(ErrUnexpectedServer, resp)
		}
		// if io.ReadAll() fails:
		//     return nil, WrapTraderError(err, StatusCode, "could not read response", nil)
		// if sonic.Unmarshall() fails
		//     return nil, WrapTraderError(err, StatusCode, "could not unmarshall", nil)
		// Note: The two above situations would wrap the errors generated by io or sonic

		// otherwise okay but the API was unhappy with our request:
		// At this point we could populate an ErrorMessage struct based on Schwab definition
		//   which contains Message string; Error []string
		return nil, WrapTraderError(ErrValidation, resp)
	default:
		return nil, fmt.Errorf("Error not defined for status %d %s", resp.StatusCode, resp.Status)
	}
}
