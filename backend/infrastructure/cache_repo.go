package infrastructure

import (
	"context"
	"time"
	errors "user_authorization/error"

	"github.com/redis/go-redis/v9"
)

type CacheRepo struct {
	Client *redis.Client
	Ctx    context.Context
}

func NewCacheRepo(client *redis.Client, ctx context.Context) *CacheRepo {
	return &CacheRepo{
		Client: client,
		Ctx:    ctx,
	}
}

func (c *CacheRepo) Set(key string, value string, expiry_time time.Duration) *errors.CustomError {
	err := c.Client.Set(c.Ctx, key, value, expiry_time).Err()
	if err != nil {
		return errors.NewCustomError("error setting cache", 500)
	}
	return nil
}

func (c *CacheRepo) Get(key string) (string, *errors.CustomError) {
	val, err := c.Client.Get(c.Ctx, key).Result()
	if err != nil {
		return "", errors.NewCustomError("error getting cache", 500)
	}
	return val, nil
}

func (c *CacheRepo) Delete(key string) *errors.CustomError {
	err := c.Client.Del(c.Ctx, key).Err()
	if err != nil {
		return errors.NewCustomError("error deleting cache", 500)
	}
	return nil
}

