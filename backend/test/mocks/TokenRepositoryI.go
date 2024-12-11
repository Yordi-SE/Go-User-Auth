// Code generated by mockery v2.50.0. DO NOT EDIT.

package mocks

import (
	errors "user_authorization/error"

	mock "github.com/stretchr/testify/mock"

	models "user_authorization/domain"
)

// TokenRepositoryI is an autogenerated mock type for the TokenRepositoryI type
type TokenRepositoryI struct {
	mock.Mock
}

// CreateToken provides a mock function with given fields: token
func (_m *TokenRepositoryI) CreateToken(token *models.Token) (*models.Token, *errors.CustomError) {
	ret := _m.Called(token)

	if len(ret) == 0 {
		panic("no return value specified for CreateToken")
	}

	var r0 *models.Token
	var r1 *errors.CustomError
	if rf, ok := ret.Get(0).(func(*models.Token) (*models.Token, *errors.CustomError)); ok {
		return rf(token)
	}
	if rf, ok := ret.Get(0).(func(*models.Token) *models.Token); ok {
		r0 = rf(token)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*models.Token)
		}
	}

	if rf, ok := ret.Get(1).(func(*models.Token) *errors.CustomError); ok {
		r1 = rf(token)
	} else {
		if ret.Get(1) != nil {
			r1 = ret.Get(1).(*errors.CustomError)
		}
	}

	return r0, r1
}

// DeleteToken provides a mock function with given fields: tokenId
func (_m *TokenRepositoryI) DeleteToken(tokenId string) *errors.CustomError {
	ret := _m.Called(tokenId)

	if len(ret) == 0 {
		panic("no return value specified for DeleteToken")
	}

	var r0 *errors.CustomError
	if rf, ok := ret.Get(0).(func(string) *errors.CustomError); ok {
		r0 = rf(tokenId)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*errors.CustomError)
		}
	}

	return r0
}

// GetTokenById provides a mock function with given fields: tokenId
func (_m *TokenRepositoryI) GetTokenById(tokenId string) (*models.Token, *errors.CustomError) {
	ret := _m.Called(tokenId)

	if len(ret) == 0 {
		panic("no return value specified for GetTokenById")
	}

	var r0 *models.Token
	var r1 *errors.CustomError
	if rf, ok := ret.Get(0).(func(string) (*models.Token, *errors.CustomError)); ok {
		return rf(tokenId)
	}
	if rf, ok := ret.Get(0).(func(string) *models.Token); ok {
		r0 = rf(tokenId)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*models.Token)
		}
	}

	if rf, ok := ret.Get(1).(func(string) *errors.CustomError); ok {
		r1 = rf(tokenId)
	} else {
		if ret.Get(1) != nil {
			r1 = ret.Get(1).(*errors.CustomError)
		}
	}

	return r0, r1
}

// SaveTokenUpdate provides a mock function with given fields: token
func (_m *TokenRepositoryI) SaveTokenUpdate(token *models.Token) *errors.CustomError {
	ret := _m.Called(token)

	if len(ret) == 0 {
		panic("no return value specified for SaveTokenUpdate")
	}

	var r0 *errors.CustomError
	if rf, ok := ret.Get(0).(func(*models.Token) *errors.CustomError); ok {
		r0 = rf(token)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*errors.CustomError)
		}
	}

	return r0
}

// NewTokenRepositoryI creates a new instance of TokenRepositoryI. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewTokenRepositoryI(t interface {
	mock.TestingT
	Cleanup(func())
}) *TokenRepositoryI {
	mock := &TokenRepositoryI{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}