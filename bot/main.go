package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"time"

	"github.com/go-telegram/bot"
	"github.com/go-telegram/bot/models"
)

type User struct {
	Name        string
	UserID      int64
	AccessToken string
	Access      []int
}

type UserData struct {
	Id   int64  `json:"id"`
	Name string `json:"name"`
}

// Глобальная переменная для проверки, что пользователь дал доступ
var authenticate struct {
	is_done bool
	code    string
}

// Send any text message to the bot after the bot has been started

// День
type Day struct {
	Name    string
	Lessons []Lesson
}

// Пара
type Lesson struct {
	Name    string
	Teacher string
	Room    string
	Comment string
	Number  int16
	Type    int8
}

type TimeOnly struct {
	Hours   int
	Minutes int
}

type TimeRange struct {
	Start TimeOnly
	End   TimeOnly
}

const (
	CLIENT_ID     = "573ff033760184359c1c"
	CLIENT_SECRET = "3fbc5b87e53a628c02c538fa7ef095ed4c8ffb6c"
)

//
// [ { start: "8:00", end: "9:30" }, { start: "9:50", end: "11:20" } ]

func createTimeOnly(hours, minutes int) TimeOnly {
	return TimeOnly{Hours: hours, Minutes: minutes}
}

var timeTable = []TimeRange{
	{Start: createTimeOnly(8, 00), End: createTimeOnly(9, 50)},
	{Start: createTimeOnly(9, 50), End: createTimeOnly(11, 30)},
	{Start: createTimeOnly(11, 30), End: createTimeOnly(13, 20)},
	{Start: createTimeOnly(13, 20), End: createTimeOnly(15, 00)},
	{Start: createTimeOnly(15, 00), End: createTimeOnly(16, 30)},
}

func convertToMinutes(hours, minutes int) int {
	return hours*60 + minutes
}

func getCurrentLessonNumber(now time.Time) int16 {
	currentLessonNum := -1

	nowMinutes := convertToMinutes(now.Hour(), now.Minute())
	startMinutesFirst := convertToMinutes(timeTable[0].Start.Hours, timeTable[0].Start.Minutes)
	endMinutesLast := convertToMinutes(timeTable[len(timeTable)-1].End.Hours, timeTable[len(timeTable)-1].End.Minutes)

	if nowMinutes < startMinutesFirst {
		return 0
	} else if nowMinutes > endMinutesLast {
		return 8
	}

	for i, timeEntry := range timeTable {
		startMinutes := convertToMinutes(timeEntry.Start.Hours, timeEntry.Start.Minutes)
		endMinutes := convertToMinutes(timeEntry.End.Hours, timeEntry.End.Minutes)

		if nowMinutes >= startMinutes && nowMinutes < endMinutes {
			currentLessonNum = i + 1
			break
		}
	}

	return int16(currentLessonNum)
}

func main() {
	go startServer()

	accessToken := getAccessToken(authenticate.code)
	userData := getUserData(accessToken)
	users := make(map[int64]*User)
	if _, ok := users[userData.Id]; !ok {
		// Добавляем пользователя с дефолтными правами
		users[userData.Id] = &User{
			Name:        userData.Name,
			UserID:      userData.Id,
			AccessToken: accessToken,
			Access:      []int{13},
		}
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	opts := []bot.Option{
		bot.WithDefaultHandler(defaultHandler),
	}

	tokenBuff, err := os.ReadFile("./token.txt")
	if err != nil {
		panic(err)
	}

	b, err := bot.New(string(tokenBuff), opts...)
	if err != nil {
		panic(err)
	}

	b.RegisterHandler(bot.HandlerTypeMessageText, "/help", bot.MatchTypeExact, helpHandler)
	b.RegisterHandler(bot.HandlerTypeMessageText, "/login", bot.MatchTypeExact, loginHandler)
	b.RegisterHandler(bot.HandlerTypeMessageText, "/nextLesson", bot.MatchTypeExact, nextLessonHandler)
	// Для дня недели
	b.RegisterHandler(bot.HandlerTypeMessageText, "/scheduleOn", bot.MatchTypeExact, scheduleOnHandler)
	b.RegisterHandler(bot.HandlerTypeMessageText, "/scheduleTomorrow", bot.MatchTypeExact, scheduleTomorrowHandler)
	b.RegisterHandler(bot.HandlerTypeMessageText, "/scheduleToday", bot.MatchTypeExact, scheduleTodayHandler)
	b.RegisterHandler(bot.HandlerTypeMessageText, "/comment", bot.MatchTypeExact, commentHandler)
	b.RegisterHandler(bot.HandlerTypeMessageText, "/whereStudents", bot.MatchTypeExact, whereStudentsHandler)
	b.RegisterHandler(bot.HandlerTypeMessageText, "/whereTeacher", bot.MatchTypeExact, whereTeacherHandler)
	b.RegisterHandler(bot.HandlerTypeMessageText, "/whenExam", bot.MatchTypeExact, whenExamHandler)
	b.RegisterHandler(bot.HandlerTypeMessageText, "/test", bot.MatchTypeExact, testHandler)

	b.Start(ctx)
}

func startServer() {
	http.HandleFunc("/oauth", handleOauth) // Вызов функции при запросе на /oauth
	http.ListenAndServe(":8080", nil)      // Запуск сервера
}

// Обработчик запроса
func handleOauth(w http.ResponseWriter, r *http.Request) {
	var responseHtml = "<html><body><h1>Вы НЕ аутентифицированы!</h1></body></html>"

	code := r.URL.Query().Get("code") // Достаем временный код из запроса
	if code != "" {
		authenticate.is_done = true
		authenticate.code = code
		responseHtml = "<html><body><h1>Вы аутентифицированы!</h1></body></html>"
	}

	fmt.Fprint(w, responseHtml) // Ответ на запрос
}
func getAccessToken(code string) string {
	// Создаём http-клиент с дефолтными настройками
	client := http.Client{}
	requestURL := "https://github.com/login/oauth/access_token"

	// Добавляем данные в виде Формы
	form := url.Values{}
	form.Add("client_id", CLIENT_ID)
	form.Add("client_secret", CLIENT_SECRET)
	form.Add("code", code)

	// Готовим и отправляем запрос
	request, _ := http.NewRequest("POST", requestURL, strings.NewReader(form.Encode()))
	request.Header.Set("Accept", "application/json") // просим прислать ответ в формате json
	response, _ := client.Do(request)
	defer response.Body.Close()

	// Достаём данные из тела ответа
	var responsejson struct {
		AccessToken string `json:"access_token"`
	}
	json.NewDecoder(response.Body).Decode(&responsejson)
	return responsejson.AccessToken
}

// Получаем информацию о пользователе
func getUserData(AccessToken string) UserData {
	// Создаём http-клиент с дефолтными настройками
	client := http.Client{}
	requestURL := "https://api.github.com/user"

	// Готовим и отправляем запрос
	request, _ := http.NewRequest("GET", requestURL, nil)
	request.Header.Set("Authorization", "Bearer "+AccessToken)
	response, _ := client.Do(request)
	defer response.Body.Close()

	var data UserData
	json.NewDecoder(response.Body).Decode(&data)
	return data
}
func whenExamHandler(ctx context.Context, b *bot.Bot, update *models.Update) {
	b.SendMessage(ctx, &bot.SendMessageParams{
		ChatID: update.Message.Chat.ID,
		Text:   "Команда ещё не реализована",
	})
}

func whereTeacherHandler(ctx context.Context, b *bot.Bot, update *models.Update) {
	b.SendMessage(ctx, &bot.SendMessageParams{
		ChatID: update.Message.Chat.ID,
		Text:   "Команда ещё не реализована",
	})
}

func whereStudentsHandler(ctx context.Context, b *bot.Bot, update *models.Update) {
	b.SendMessage(ctx, &bot.SendMessageParams{
		ChatID: update.Message.Chat.ID,
		Text:   "Команда ещё не реализована",
	})
}

func commentHandler(ctx context.Context, b *bot.Bot, update *models.Update) {
	b.SendMessage(ctx, &bot.SendMessageParams{
		ChatID: update.Message.Chat.ID,
		Text:   "Команда ещё не реализована",
	})
}

func scheduleOnHandler(ctx context.Context, b *bot.Bot, update *models.Update) {
	b.SendMessage(ctx, &bot.SendMessageParams{
		ChatID: update.Message.Chat.ID,
		Text:   "Команда ещё не реализована",
	})
}

func scheduleTomorrowHandler(ctx context.Context, b *bot.Bot, update *models.Update) {
	days, err := getDays()
	if authenticate.is_done == false {
		b.SendMessage(ctx, &bot.SendMessageParams{
			ChatID: update.Message.Chat.ID,
			Text:   "Пожалуйста пройдите авторизацию /login",
		})
		getAccessToken(authenticate.code)
		return
	}
	if checkForError(ctx, b, update, err) == false {
		return
	}

	now := time.Now()
	weekday := convertWeekdayToNormal(now.Weekday()) + 1

	// Создаём построитель строк (strings.Builder)
	var builder strings.Builder

	builder.WriteString(days[weekday].Name)
	builder.WriteString(":\n")

	// Проходим по всем парам и конвертируем их в строку
	for _, lesson := range days[weekday].Lessons {
		// Добавляем эту строку к stringBuilder
		builder.WriteString(lessonToString(lesson))
		builder.WriteString("\n")
	}
	b.SendMessage(ctx, &bot.SendMessageParams{
		ChatID: update.Message.Chat.ID,
		Text:   builder.String(),
	})
}

func getDays() ([]Day, error) {
	fileContent, err := os.ReadFile("./json/lessons_odd.json")
	if err != nil {
		return nil, err
	}

	var days []Day
	err = json.Unmarshal(fileContent, &days)
	if err != nil {
		return nil, err
	}

	return days, nil
}

func scheduleTodayHandler(ctx context.Context, b *bot.Bot, update *models.Update) {
	if authenticate.is_done == false {
		b.SendMessage(ctx, &bot.SendMessageParams{
			ChatID: update.Message.Chat.ID,
			Text:   "Пожалуйста пройдите авторизацию /login",
		})
		getAccessToken(authenticate.code)
		return
	}
	days, err := getDays()
	if checkForError(ctx, b, update, err) == false {
		return
	}

	now := time.Now()
	weekday := convertWeekdayToNormal(now.Weekday())

	// Создаём построитель строк (strings.Builder)
	var builder strings.Builder

	builder.WriteString(days[weekday].Name)
	builder.WriteString(":\n")

	// Проходим по всем парам и конвертируем их в строку
	for _, lesson := range days[weekday].Lessons {
		// Добавляем эту строку к stringBuilder
		builder.WriteString(lessonToString(lesson))
		builder.WriteString("\n")
	}

	// Отправляем в телеграм полную строчку
	b.SendMessage(ctx, &bot.SendMessageParams{
		ChatID: update.Message.Chat.ID,
		Text:   builder.String(),
	})
}

func lessonToString(lesson Lesson) string {
	var lessonType string
	if lesson.Type == 0 {
		lessonType = "Лекция"
	} else if lesson.Type == 1 {
		lessonType = "Практика"
	} else {
		lessonType = "Неизвестный тип"
	}

	return strconv.Itoa(int(lesson.Number)) + ") '" + lesson.Name + "' " + lessonType + " " + lesson.Teacher + " (" + lesson.Room + ")"
}

func convertWeekdayToNormal(weekday time.Weekday) int8 {
	var temp = int8(weekday - 1)
	// Воскресенье
	if temp == -1 {
		return 6
	}

	return temp
}

func checkForError(ctx context.Context, b *bot.Bot, update *models.Update, err error) bool {
	if err != nil {
		b.SendMessage(ctx, &bot.SendMessageParams{
			ChatID: update.Message.Chat.ID,
			Text:   "Произошла ошибка: " + err.Error(),
		})
		return false
	}

	return true
}

func nextLessonHandler(ctx context.Context, b *bot.Bot, update *models.Update) {
	if authenticate.is_done == false {
		b.SendMessage(ctx, &bot.SendMessageParams{
			ChatID: update.Message.Chat.ID,
			Text:   "Пожалуйста пройдите авторизацию /login",
		})
		getAccessToken(authenticate.code)
		return
	}
	days, err := getDays()
	if checkForError(ctx, b, update, err) == false {
		return
	}

	now := time.Now()
	weekday := convertWeekdayToNormal(now.Weekday())

	// Определить какая сейчас идёт пара
	currentLessonNumber := getCurrentLessonNumber(now)

	// Пройтись по дню, найти первую пару, которая больше текущего номера
	var nextLesson Lesson
	found := false
	for _, lesson := range days[weekday].Lessons {
		if lesson.Number > currentLessonNumber {
			nextLesson = lesson
			found = true
			break
		}
	}

	if found == false {
		b.SendMessage(ctx, &bot.SendMessageParams{
			ChatID: update.Message.Chat.ID,
			Text:   "Текущая пара: " + strconv.Itoa(int(currentLessonNumber)) + "\nНе смог найти следующую пару :(",
		})
		return
	}

	b.SendMessage(ctx, &bot.SendMessageParams{
		ChatID: update.Message.Chat.ID,
		Text:   "Текущая пара: " + strconv.Itoa(int(currentLessonNumber)) + "\nСледующая, пара:\n" + lessonToString(nextLesson),
	})
}

func loginHandler(ctx context.Context, b *bot.Bot, update *models.Update) {
	if authenticate.is_done == false {
		b.SendMessage(ctx, &bot.SendMessageParams{
			ChatID: update.Message.Chat.ID,
			Text:   "Пожалуйста пройдите авторизацию по ссылке:https://github.com/login/oauth/authorize?client_id=573ff033760184359c1c",
		})
		getAccessToken(authenticate.code)
	}
	if authenticate.is_done == true {
		b.SendMessage(ctx, &bot.SendMessageParams{
			ChatID: update.Message.Chat.ID,
			Text:   "Добро пожаловать",
		})
	}
}

func helpHandler(ctx context.Context, b *bot.Bot, update *models.Update) {
	commands := []string{
		"/help",
		"/login",
		"/nextLesson",
		"/scheduleOn",
		"/scheduleTomorrow",
		"/scheduleToday",
		"/comment",
		"/whereStudents",
		"/whereTeacher",
		"/whenExam",
		"/scheduleOnJson",
	}
	b.SendMessage(ctx, &bot.SendMessageParams{
		ChatID: update.Message.Chat.ID,
		Text:   "Доступные команды:\n" + strings.Join(commands, ", "),
	})
}

func helloHandler(ctx context.Context, b *bot.Bot, update *models.Update) {
	b.SendMessage(ctx, &bot.SendMessageParams{
		ChatID:    update.Message.Chat.ID,
		Text:      "Привет, *" + bot.EscapeMarkdown(update.Message.From.FirstName) + "*",
		ParseMode: models.ParseModeMarkdown,
	})
}

//	 Name    string
//		Teacher string
//		Room    string
//		Count   int16
//		Day     int16
func testHandler(ctx context.Context, b *bot.Bot, update *models.Update) {
	b.SendMessage(ctx, &bot.SendMessageParams{
		ChatID: update.Message.Chat.ID,
		Text:   "Выполнил команду TEST",
	})
}

func defaultHandler(ctx context.Context, b *bot.Bot, update *models.Update) {
	b.SendMessage(ctx, &bot.SendMessageParams{
		ChatID: update.Message.Chat.ID,
		Text:   "Используйте /help для списка команд",
	})
}
