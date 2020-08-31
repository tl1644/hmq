package acl

type aclAuth struct {
	config *ACLConfig
	userman *UserMagager
}

func Init() *aclAuth {
	aclConfig, err := AclConfigLoad("./plugins/auth/authfile/acl.conf")
	if err != nil {
		panic(err)
	}
	um, err := UserMagagerInit("./plugins/auth/authfile/users.conf")
	if err != nil {
		panic(err)
	}
	return &aclAuth{
		config: aclConfig,
		userman: um,
	}
}

func (a *aclAuth) CheckConnect(clientID, username, password string) bool {
	return userman.CheckCredentials(username,password)
}

func (a *aclAuth) CheckACL(action, clientID, username, ip, topic string) bool {
	return checkTopicAuth(a.config, action, username, ip, clientID, topic)
}
