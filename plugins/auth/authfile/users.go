package acl

import (
	"fmt"
	"log"
	"errors"
	"bufio"
	"io"
	"os"
	"strings"
	"golang.org/x/crypto/bcrypt"
)

type UserInfo struct {
	UserName	string
	PassHash	string
}

type UserMagager struct {
	File	string
	Users	[]*UserInfo
}

func UserMagagerInit(pFile string) (*UserMagager, error) {
	um := &UserMagager{
		File: pFile,
		Users: make([]*UserInfo, 0, 4),
	}
	err := um.Prase()
	if err != nil {
		return nil, err
	}
	return um, nil
}

func (c *UserMagager) Prase() error {
	f, err := os.Open(c.File)
	defer f.Close()
	if err != nil {
		return err
	}
	buf := bufio.NewReader(f)
	var parseErr error
	for {
		line, err := buf.ReadString('\n')
		line = strings.TrimSpace(line)
		if isComment(line) {
			continue
		}
		if line == "" {
			return parseErr
		}
		//fmt.Println(line)
		tmpArr := strings.Fields(line)
		if len(tmpArr) != 2 {
			parseErr = errors.New("\"" + line + "\" format is error")
			break
		}

		nextUser := &UserInfo{
			UserName:	tmpArr[0],
			PassHash:	tmpArr[1],
		}
		//fmt.Println(nextUser)
		c.Users = append(c.Users, nextUser)
		if err != nil {
			if err != io.EOF {
				parseErr = err
			}
			break
		}
	}
	return parseErr
}

func (c *UserMagager) CheckCredentials(pUser, pPassword string) bool {
	for _, user := range c.Users {
		if user.UserName == pUser {
			if err := bcrypt.CompareHashAndPassword([]byte(user.PassHash), []byte(pPassword)); err == nil {
				return true
			}
		}
    }
	return false
}

func isComment(line string) bool {
	if strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "//") || strings.HasPrefix(line, "*") {
		return true
	} else {
		return false
	}
} 
