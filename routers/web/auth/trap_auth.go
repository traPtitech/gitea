package auth

import (
	"fmt"
	"net/url"

	"code.gitea.io/gitea/models/user"
	"code.gitea.io/gitea/modules/log"
	"code.gitea.io/gitea/modules/optional"
	"code.gitea.io/gitea/modules/setting"
	"code.gitea.io/gitea/services/context"
	user_service "code.gitea.io/gitea/services/user"

	"github.com/golang-jwt/jwt/v5"
)

func TrapSignIn(ctx *context.Context) {
	// Check auto-login.
	if CheckAutoLogin(ctx) {
		return
	}

	token := ctx.GetSiteCookie("traP_token")
	if user := getUserFromTrapToken(ctx, token); user != nil {
		handleSignIn(ctx, user, false)
	} else {
		ctx.Redirect("https://portal.trap.jp/login?redirect=" + url.QueryEscape(setting.AppURL+"user/login"))
	}
}

func getUserFromTrapToken(ctx *context.Context, tokenString string) *user.User {
	if tokenString == "" {
		log.Warn("No token")
		return nil
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		pubKey, _ := jwt.ParseRSAPublicKeyFromPEM(pubKeyPEM)
		return pubKey, nil
	})

	if err != nil || !token.Valid {
		log.Warn("Failed to parse token: %v", err)
		return nil
	}

	data := token.Claims.(jwt.MapClaims)
	id := data["id"].(string)
	email := data["email"].(string)
	log.Debug("traP token accepted: %s", id)

	u, _ := user.GetUserByName(ctx, id)
	if u == nil {
		u = &user.User{
			Name:     id,
			Email:    email,
			Passwd:   "",
			IsActive: true,
		}
		overwrite := &user.CreateUserOverwriteOptions{
			IsRestricted: optional.Some(false),
			IsActive:     optional.Some(true),
		}
		if err := user.CreateUser(ctx, u, &user.Meta{}, overwrite); err != nil {
			log.ErrorWithSkip(3, "Failed to create account: %v", err)
			return nil
		}
		log.Trace("Account created: %s", u.Name)
	}

	opts := user_service.UpdateOptions{
		SetLastLogin: true,
	}
	if err := user_service.UpdateUser(ctx, u, &opts); err != nil {
		log.ErrorWithSkip(3, "Failed to update user: %v", err)
		return nil
	}

	if err := user_service.ReplacePrimaryEmailAddress(ctx, u, email); err != nil {
		log.ErrorWithSkip(3, "Failed to update email: %v", err)
		return nil
	}

	return u
}

var pubKeyPEM = []byte(`-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAraewUw7V1hiuSgUvkly9
X+tcIh0e/KKqeFnAo8WR3ez2tA0fGwM+P8sYKHIDQFX7ER0c+ecTiKpo/Zt/a6AO
gB/zHb8L4TWMr2G4q79S1gNw465/SEaGKR8hRkdnxJ6LXdDEhgrH2ZwIPzE0EVO1
eFrDms1jS3/QEyZCJ72oYbAErI85qJDF/y/iRgl04XBK6GLIW11gpf8KRRAh4vuh
g5/YhsWUdcX+uDVthEEEGOikSacKZMFGZNi8X8YVnRyWLf24QTJnTHEv+0EStNrH
HnxCPX0m79p7tBfFC2ha2OYfOtA+94ZfpZXUi2r6gJZ+dq9FWYyA0DkiYPUq9QMb
OQIDAQAB
-----END PUBLIC KEY-----`)
