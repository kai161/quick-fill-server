package shared

import (
	"context"
	"os"
	"sync"

	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	pool     *pgxpool.Pool
	poolOnce sync.Once
)

// DB 返回全局连接池（懒初始化，Vercel 每个函数实例只建一次）
func DB() *pgxpool.Pool {
	poolOnce.Do(func() {
		dsn := os.Getenv("POSTGRES_URL")
		if dsn == "" {
			panic("环境变量 POSTGRES_URL 未设置")
		}
		var err error
		pool, err = pgxpool.New(context.Background(), dsn)
		if err != nil {
			panic("数据库连接失败: " + err.Error())
		}
		migrate(pool)
	})
	return pool
}

func migrate(p *pgxpool.Pool) {
	_, err := p.Exec(context.Background(), `
		CREATE TABLE IF NOT EXISTS users (
			id         BIGSERIAL PRIMARY KEY,
			email      TEXT      UNIQUE NOT NULL,
			password   TEXT      NOT NULL,
			is_pro     BOOLEAN   NOT NULL DEFAULT false,
			created_at BIGINT    NOT NULL
		)
	`)
	if err != nil {
		panic("migrate 失败: " + err.Error())
	}
}
