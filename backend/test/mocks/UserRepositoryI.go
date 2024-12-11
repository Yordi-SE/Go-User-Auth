// Code generated by mockery v2.50.0. DO NOT EDIT.

package mocks

import (
	errors "user_authorization/error"

	mock "github.com/stretchr/testify/mock"

	models "user_authorization/domain"
)

// UserRepositoryI is an autogenerated mock type for the UserRepositoryI type
type UserRepositoryI struct {
	mock.Mock
}

// CreateUser provides a mock function with given fields: user
func (_m *UserRepositoryI) CreateUser(user *models.User) (*models.User, *errors.CustomError) {
	ret := _m.Called(user)

	if len(ret) == 0 {
		panic("no return value specified for CreateUser")
	}

	var r0 *models.User
	var r1 *errors.CustomError
	if rf, ok := ret.Get(0).(func(*models.User) (*models.User, *errors.CustomError)); ok {
		return rf(user)
	}
	if rf, ok := ret.Get(0).(func(*models.User) *models.User); ok {
		r0 = rf(user)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*models.User)
		}
	}

	if rf, ok := ret.Get(1).(func(*models.User) *errors.CustomError); ok {
		r1 = rf(user)
	} else {
		if ret.Get(1) != nil {
			r1 = ret.Get(1).(*errors.CustomError)
		}
	}

	return r0, r1
}

// DeleteUser provides a mock function with given fields: userId
func (_m *UserRepositoryI) DeleteUser(userId string) *errors.CustomError {
	ret := _m.Called(userId)

	if len(ret) == 0 {
		panic("no return value specified for DeleteUser")
	}

	var r0 *errors.CustomError
	if rf, ok := ret.Get(0).(func(string) *errors.CustomError); ok {
		r0 = rf(userId)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*errors.CustomError)
		}
	}

	return r0
}

// GetUserByEmail provides a mock function with given fields: email
func (_m *UserRepositoryI) GetUserByEmail(email string) (*models.User, *errors.CustomError) {
	ret := _m.Called(email)

	if len(ret) == 0 {
		panic("no return value specified for GetUserByEmail")
	}

	var r0 *models.User
	var r1 *errors.CustomError
	if rf, ok := ret.Get(0).(func(string) (*models.User, *errors.CustomError)); ok {
		return rf(email)
	}
	if rf, ok := ret.Get(0).(func(string) *models.User); ok {
		r0 = rf(email)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*models.User)
		}
	}

	if rf, ok := ret.Get(1).(func(string) *errors.CustomError); ok {
		r1 = rf(email)
	} else {
		if ret.Get(1) != nil {
			r1 = ret.Get(1).(*errors.CustomError)
		}
	}

	return r0, r1
}

// GetUserById provides a mock function with given fields: userId
func (_m *UserRepositoryI) GetUserById(userId string) (*models.User, *errors.CustomError) {
	ret := _m.Called(userId)

	if len(ret) == 0 {
		panic("no return value specified for GetUserById")
	}

	var r0 *models.User
	var r1 *errors.CustomError
	if rf, ok := ret.Get(0).(func(string) (*models.User, *errors.CustomError)); ok {
		return rf(userId)
	}
	if rf, ok := ret.Get(0).(func(string) *models.User); ok {
		r0 = rf(userId)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*models.User)
		}
	}

	if rf, ok := ret.Get(1).(func(string) *errors.CustomError); ok {
		r1 = rf(userId)
	} else {
		if ret.Get(1) != nil {
			r1 = ret.Get(1).(*errors.CustomError)
		}
	}

	return r0, r1
}

// GetUsers provides a mock function with given fields: page
func (_m *UserRepositoryI) GetUsers(page int) ([]models.User, *errors.CustomError) {
	ret := _m.Called(page)

	if len(ret) == 0 {
		panic("no return value specified for GetUsers")
	}

	var r0 []models.User
	var r1 *errors.CustomError
	if rf, ok := ret.Get(0).(func(int) ([]models.User, *errors.CustomError)); ok {
		return rf(page)
	}
	if rf, ok := ret.Get(0).(func(int) []models.User); ok {
		r0 = rf(page)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]models.User)
		}
	}

	if rf, ok := ret.Get(1).(func(int) *errors.CustomError); ok {
		r1 = rf(page)
	} else {
		if ret.Get(1) != nil {
			r1 = ret.Get(1).(*errors.CustomError)
		}
	}

	return r0, r1
}

// SaveUserUpdate provides a mock function with given fields: user
func (_m *UserRepositoryI) SaveUserUpdate(user *models.User) *errors.CustomError {
	ret := _m.Called(user)

	if len(ret) == 0 {
		panic("no return value specified for SaveUserUpdate")
	}

	var r0 *errors.CustomError
	if rf, ok := ret.Get(0).(func(*models.User) *errors.CustomError); ok {
		r0 = rf(user)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*errors.CustomError)
		}
	}

	return r0
}

// UpdateUserToken provides a mock function with given fields: userId, accessToken, refreshToken
func (_m *UserRepositoryI) UpdateUserToken(userId string, accessToken string, refreshToken string) *errors.CustomError {
	ret := _m.Called(userId, accessToken, refreshToken)

	if len(ret) == 0 {
		panic("no return value specified for UpdateUserToken")
	}

	var r0 *errors.CustomError
	if rf, ok := ret.Get(0).(func(string, string, string) *errors.CustomError); ok {
		r0 = rf(userId, accessToken, refreshToken)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*errors.CustomError)
		}
	}

	return r0
}

// NewUserRepositoryI creates a new instance of UserRepositoryI. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewUserRepositoryI(t interface {
	mock.TestingT
	Cleanup(func())
}) *UserRepositoryI {
	mock := &UserRepositoryI{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}