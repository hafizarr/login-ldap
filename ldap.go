package main

import (
	"fmt"

	"github.com/go-ldap/ldap"
)

// const connection to server
const (
	ldapServer   = "ldap.forumsys.com"
	ldapPort     = 389
	ldapBindDN   = "cn=read-only-admin,dc=example,dc=com"
	ldapPassword = "password"
	ldapSearchDN = "dc=example,dc=com" // for operation search
)

type UserLDAPData struct {
	ID          string
	Email       string
	Name        string
	FullName    string
	PhoneNumber string
}

func AuthUsingLDAP(username, password string) (bool, *UserLDAPData, error) {
	// ldap connection initialization, handshake to server directory
	l, err := ldap.Dial("tcp", fmt.Sprintf("%s:%d", ldapServer, ldapPort))
	if err != nil {
		return false, nil, err
	}
	defer l.Close()

	// bind operation
	err = l.Bind(ldapBindDN, ldapPassword)
	if err != nil {
		return false, nil, err
	}

	// set search req with uid or username
	searchRequest := ldap.NewSearchRequest(
		ldapSearchDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		fmt.Sprintf("(&(objectClass=organizationalPerson)(uid=%s))", username), // search with uid
		[]string{"dn", "cn", "sn", "mail", "telephoneNumber"},                  // get data attribute
		nil,
	)

	sr, err := l.Search(searchRequest)
	if err != nil {
		return false, nil, err
	}

	if len(sr.Entries) == 0 {
		return false, nil, fmt.Errorf("User not found")
	}
	entry := sr.Entries[0]

	err = l.Bind(entry.DN, password)
	if err != nil {
		return false, nil, err
	}

	data := new(UserLDAPData)
	data.ID = username

	for _, attr := range entry.Attributes {
		switch attr.Name {
		case "sn":
			data.Name = attr.Values[0]
		case "mail":
			data.Email = attr.Values[0]
		case "cn":
			data.FullName = attr.Values[0]
		case "telephoneNumber":
			data.PhoneNumber = attr.Values[0]
		}
	}

	return true, data, nil
}
