package infrastructure

import (
	"context"
	"mime/multipart"
	"os"
	errors "user_authorization/error"

	"github.com/cloudinary/cloudinary-go"
	"github.com/cloudinary/cloudinary-go/api/uploader"
)

type FileUploadManager struct {
	cld *cloudinary.Cloudinary
}

func NewFileUploadManager(cld *cloudinary.Cloudinary) *FileUploadManager {
	return &FileUploadManager{
		cld: cld,
	}
}

func (f *FileUploadManager) UploadFile(userID string,file *multipart.FileHeader) (string, *errors.CustomError) {
	// Remove from local
	defer func() {
		os.Remove("../assets/uploads/" + file.Filename)
	}()
	
	// Upload the image on the cloud
	var ctx = context.Background()
	resp, err := f.cld.Upload.Upload(ctx, "../assets/uploads/"+file.Filename, uploader.UploadParams{PublicID: "go_auth_profile_pic" + "-" + file.Filename + "-" + userID})

	if err != nil {
		return "", errors.NewCustomError(err.Error(), 500)
	}

	// Return the image url
	return resp.SecureURL, nil
}

func (f *FileUploadManager) DeleteFile(userID string, file *multipart.FileHeader) *errors.CustomError {
	_, err := f.cld.Upload.Destroy(context.Background(), uploader.DestroyParams{PublicID: "go_auth_profile_pic" + "-" + file.Filename + "-" + userID})
	if err != nil {
		return errors.NewCustomError(err.Error(), 500)
	}
	return nil
}
