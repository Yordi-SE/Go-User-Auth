// Code generated by mockery v2.50.0. DO NOT EDIT.

package mocks

import (
	errors "user_authorization/error"

	mock "github.com/stretchr/testify/mock"

	multipart "mime/multipart"
)

// FileUploadManagerI is an autogenerated mock type for the FileUploadManagerI type
type FileUploadManagerI struct {
	mock.Mock
}

// DeleteFile provides a mock function with given fields: userID, file
func (_m *FileUploadManagerI) DeleteFile(userID string, file *multipart.FileHeader) *errors.CustomError {
	ret := _m.Called(userID, file)

	if len(ret) == 0 {
		panic("no return value specified for DeleteFile")
	}

	var r0 *errors.CustomError
	if rf, ok := ret.Get(0).(func(string, *multipart.FileHeader) *errors.CustomError); ok {
		r0 = rf(userID, file)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*errors.CustomError)
		}
	}

	return r0
}

// UploadFile provides a mock function with given fields: userID, file
func (_m *FileUploadManagerI) UploadFile(userID string, file *multipart.FileHeader) (string, *errors.CustomError) {
	ret := _m.Called(userID, file)

	if len(ret) == 0 {
		panic("no return value specified for UploadFile")
	}

	var r0 string
	var r1 *errors.CustomError
	if rf, ok := ret.Get(0).(func(string, *multipart.FileHeader) (string, *errors.CustomError)); ok {
		return rf(userID, file)
	}
	if rf, ok := ret.Get(0).(func(string, *multipart.FileHeader) string); ok {
		r0 = rf(userID, file)
	} else {
		r0 = ret.Get(0).(string)
	}

	if rf, ok := ret.Get(1).(func(string, *multipart.FileHeader) *errors.CustomError); ok {
		r1 = rf(userID, file)
	} else {
		if ret.Get(1) != nil {
			r1 = ret.Get(1).(*errors.CustomError)
		}
	}

	return r0, r1
}

// NewFileUploadManagerI creates a new instance of FileUploadManagerI. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewFileUploadManagerI(t interface {
	mock.TestingT
	Cleanup(func())
}) *FileUploadManagerI {
	mock := &FileUploadManagerI{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}