## Управление миграциями
- Создание новой миграции: `migrate create -ext sql -dir migrations -seq <имя_миграции>`
- Применение миграций: автоматически при запуске приложения
- Откат последней миграции: `migrate -source file://migrations -database "postgres://user:pass@localhost:5432/dbname?sslmode=disable" down 1`