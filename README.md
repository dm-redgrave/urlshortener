# Документация API для сервиса сокращения ссылок

## Регистрация пользователей

### POST `/auth/register`

Создаёт нового пользователя с указанным email и генерирует пароль.

#### Параметры запроса

| Название | Тип   | Обязательный | Описание                      |
|----------|-------|--------------|-------------------------------|
| `email`  | String| Да        | Email пользователя для регистрации |

#### Пример тела запроса (JSON):

```json
{
    "email": "user@example.com"
}
```

#### Пример ответа:

```json
{
    "message": "User created",
    "generated_password": "A1b2C3d4"
}
```

---

## Создание короткой ссылки

### POST `/links/shorten`

Создаёт короткую ссылку для указанного URL.

#### Параметры запроса (тело запроса, JSON)

| Название       | Тип      | Обязательный | Описание                           |
|----------------|----------|--------------|------------------------------------|
| `url`          | String   | Да        | Оригинальный URL                   |
| `custom_alias` | String   | Нет       | Пользовательский короткий код      |
| `expires_at`   | DateTime | Нет       | Дата истечения ссылки (ISO формат) |

#### Параметры запроса (query-параметры)

| Название   | Тип    | Обязательный | Описание                   |
|------------|--------|--------------|----------------------------|
| `email`    | String | Нет       | Email пользователя         |
| `password` | String | Нет       | Пароль пользователя        |

#### Пример тела запроса:

```json
{
    "url": "https://example.com",
    "custom_alias": "myalias",
    "expires_at": "2025-04-01T00:00:00"
}
```

#### Пример ответа:

```json
{
    "short_url": "http://127.0.0.1/links/myalias",
    "short_code": "myalias"
}
```

---

## Поиск ссылки по оригинальному URL

### GET `/links/search`

Возвращает сокращённый код по оригинальному URL.

#### Параметры запроса

| Название | Тип    | Обязательный | Описание                   |
|----------|--------|--------------|----------------------------|
| `url`    | String | Да        | Оригинальный URL для поиска|

#### Пример запроса:

```
GET /links/search?url=https://example.com
```

#### Пример ответа:

```json
{
    "short_code": "myalias",
    "original_url": "https://example.com"
}
```

---

## Переход по короткой ссылке

### GET `/links/{short_code}`

Перенаправляет на оригинальный URL.

#### Параметры пути

| Название     | Тип    | Обязательный | Описание             |
|--------------|--------|--------------|----------------------|
| `short_code` | String | Да        | Короткий код ссылки  |

#### Пример запроса:

```
GET /links/myalias
```

#### Возможные ответы:

- **HTTP 307**: перенаправление на оригинальный URL  
- **HTTP 404**: ссылка не найдена  
- **HTTP 410**: срок действия ссылки истёк

---

## Получение статистики по ссылке

### GET `/links/{short_code}/stats`

Возвращает статистику по ссылке.

#### Параметры пути

| Название     | Тип    | Обязательный | Описание             |
|--------------|--------|--------------|----------------------|
| `short_code` | String | Да        | Короткий код ссылки  |

#### Пример запроса:

```
GET /links/myalias/stats
```

#### Пример ответа:

```json
{
    "original_url": "https://example.com",
    "created_at": "2025-03-30T12:00:00",
    "last_accessed_at": "2025-03-31T14:00:00",
    "click_count": 15,
    "expires_at": "2025-04-01T00:00:00"
}
```

---

## Удаление ссылки (только владелец)

### DELETE `/links/{short_code}`

Удаляет ссылку. Требует авторизации владельца.

#### Параметры пути

| Название     | Тип    | Обязательный | Описание             |
|--------------|--------|--------------|----------------------|
| `short_code` | String | Да        | Короткий код ссылки  |

#### Параметры запроса (авторизация)

| Название   | Тип    | Обязательный | Описание           |
|------------|--------|--------------|--------------------|
| `email`    | String | Да        | Email владельца    |
| `password` | String | Да        | Пароль владельца   |

#### Пример запроса:

```
DELETE /links/myalias?email=user@example.com&password=secret
```

#### Пример ответа:

```json
{
    "message": "Link deleted"
}
```

---

## Изменение короткого кода ссылки (только владелец)

### PUT `/links/{short_code}`

Позволяет изменить короткий код существующей ссылки.

#### Параметры пути

| Название     | Тип    | Обязательный | Описание                  |
|--------------|--------|--------------|---------------------------|
| `short_code` | String | Да        | Текущий короткий код ссылки|

#### Параметры запроса

| Название         | Тип    | Обязательный | Описание                |
|------------------|--------|--------------|-------------------------|
| `new_short_code` | String | Да        | Новый короткий код      |
| `email`          | String | Да        | Email владельца         |
| `password`       | String | Да        | Пароль владельца        |

#### Пример запроса:

```
PUT /links/myalias?new_short_code=newalias&email=user@example.com&password=secret
```

#### Пример ответа:

```json
{
    "message": "Link updated"
}
```

---

## Настройка срока действия ссылок (скрытый endpoint)

### POST `/config/set_expiration`

Устанавливает период (в днях) для автоматического удаления неиспользуемых ссылок. Доступ ограничен токеном администратора.

#### Параметры запроса

| Название       | Тип    | Обязательный | Описание                            |
|----------------|--------|--------------|-------------------------------------|
| `days`         | Integer| Да        | Количество дней для истечения ссылок|
| `access_token` | String | Да        | Админ-токен (`ADMIN_TOKEN`)         |

#### Пример запроса:

```
POST /config/set_expiration?days=15&access_token=your_admin_token
```

#### Пример ответа:

```json
{
    "message": "Default expiration changed to 15"
}
```

---

## Инструкция по запуску

Для деплоя нашего сервиса воспользуемся облачной платформой render.com.

1. Проходим процесс регистрации.
2. Создаём приложение типа веб-сервис (Add New -> Web Service):

![image](https://github.com/user-attachments/assets/b232106e-7efe-4ec3-a20e-69b921990f85)

3. Указываем ссылку на репозиторий и нажимаем Connect:

![image](https://github.com/user-attachments/assets/0807aaa7-0783-47c8-bd4c-071b939fc518)

4. Устанавливаем имя сервиса:

![image](https://github.com/user-attachments/assets/62b8f8c9-3e32-452b-b55f-e7937d795f9a)

5. Выбираем тарифный план:

![image](https://github.com/user-attachments/assets/68ba8359-64c1-4197-b21b-46586f16d8b5)

6. Так же потребуется указать 2 переменные среды окружения (для доступа к закрытому endpoint и для формирования ссылок):

![image](https://github.com/user-attachments/assets/f132d101-5142-476a-945d-0f109b5b9a8b)

7. Нажимаем Deploy Web Service и ожидаем завершения процесса. Как результат - работающий сервис:

![image](https://github.com/user-attachments/assets/861dd08d-4aa6-44a9-a6cf-5d1f8e65288c)

8. Проверяем:

![image](https://github.com/user-attachments/assets/f82877b6-2c88-4870-9266-af1d9a083e91)

## Структура базы данных (SQLite)

### Таблица `users`

| Поле            | Тип         | Описание                      |
|-----------------|-------------|-------------------------------|
| `id`            | INTEGER (PK)| Уникальный идентификатор      |
| `email`         | TEXT        | Email пользователя   |
| `password_hash` | TEXT        | Хеш пароля                    |
| `created_at`    | DATETIME    | Дата регистрации              |

### Таблица `links`

| Поле               | Тип            | Описание                           |
|--------------------|----------------|------------------------------------|
| `id`               | INTEGER (PK)   | Уникальный идентификатор           |
| `short_code`       | TEXT           | Короткий код ссылки        |
| `original_url`     | TEXT           | Исходный URL                       |
| `user_id`          | INTEGER (FK)   | Ссылка на `users.id` |
| `created_at`       | DATETIME       | Дата создания                      |
| `last_accessed_at` | DATETIME       | Дата последнего перехода           |
| `click_count`      | INTEGER        | Счётчик переходов                  |
| `expires_at`       | DATETIME       | Дата истечения срока действия      |
