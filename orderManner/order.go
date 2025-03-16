package orderManner

import (
	"database/sql"
	"fmt"
	"html/template"
	"net/http"
	"strconv"
	"strings"
)

// OrderManager 订单管理器
type OrderManager struct {
	DB       *sql.DB
	GetUser  func(r *http.Request) (email string, loggedIn bool)
	Template *template.Template
}

// NewOrderManager 创建新的订单管理器
func NewOrderManager(db *sql.DB, getUserFunc func(r *http.Request) (string, bool)) (*OrderManager, error) {
	// 加载模板
	tmpl, err := template.ParseFiles("templates/order.html")
	if err != nil {
		return nil, err
	}

	return &OrderManager{
		DB:       db,
		GetUser:  getUserFunc,
		Template: tmpl,
	}, nil
}

// HandleOrderRequest 处理订单请求
func (om *OrderManager) HandleOrderRequest(w http.ResponseWriter, r *http.Request) {
	// 检查用户是否登录
	email, loggedIn := om.GetUser(r)
	if !loggedIn {
		// 重定向到登录页面，并保存当前URL
		http.Redirect(w, r, "/login?redirect="+r.URL.RequestURI(), http.StatusFound)
		return
	}

	// 处理GET请求中的订单参数
	if r.Method == http.MethodGet && r.URL.RawQuery != "" {
		om.handleNewOrderFromGet(w, r, email)
		return
	}

	// 处理表单提交
	if r.Method == http.MethodPost {
		om.handleOrderUpdate(w, r, email)
		return
	}

	// 显示订单列表
	om.showOrderList(w, r, email)
}

// handleNewOrderFromGet 处理GET请求中的新订单
// 格式：domain/?{seller or buyer}+{post link}+{unix time}
func (om *OrderManager) handleNewOrderFromGet(w http.ResponseWriter, r *http.Request, email string) {
	query := r.URL.RawQuery
	parts := strings.Split(query, "+")

	if len(parts) < 3 {
		http.Error(w, "格式错误：缺少必要参数", http.StatusBadRequest)
		return
	}

	role := parts[0] // seller 或 buyer
	postLink := parts[1]
	timeStr := parts[2]

	// 获取价格，如果有的话
	price := 0
	if len(parts) > 3 {
		p, err := strconv.Atoi(parts[3])
		if err == nil && p > 0 {
			price = p
		}
	}

	// 如果没有指定价格，使用默认值
	if price == 0 {
		price = 100 // 默认价格
	}

	// 解析时间戳
	timestamp, err := strconv.ParseInt(timeStr, 10, 64)
	if err != nil {
		http.Error(w, "无效的时间戳", http.StatusBadRequest)
		return
	}

	// 根据角色设置卖家和买家
	var seller, buyer string
	if role == "seller" {
		seller = email
		buyer = "unknown" // 可以在订单页面更新
	} else if role == "buyer" {
		buyer = email
		seller = "unknown" // 可以在订单页面更新
	} else {
		http.Error(w, "无效的角色参数", http.StatusBadRequest)
		return
	}

	// 检查订单是否已存在
	existingOrder, _ := GetOrderByDetails(om.DB, email, postLink, timestamp)
	if existingOrder != nil {
		// 订单已存在，直接显示订单页面
		http.Redirect(w, r, "/orders", http.StatusFound)
		return
	}

	// 创建新订单
	_, err = CreateOrder(om.DB, seller, buyer, price, postLink)
	if err != nil {
		http.Error(w, "创建订单失败: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// 重定向到订单列表页面
	http.Redirect(w, r, "/orders", http.StatusFound)
}

// handleOrderUpdate 处理订单状态更新
func (om *OrderManager) handleOrderUpdate(w http.ResponseWriter, r *http.Request, email string) {
	r.ParseForm()

	orderIDStr := r.FormValue("order_id")
	action := r.FormValue("action")

	orderID, err := strconv.ParseInt(orderIDStr, 10, 64)
	if err != nil {
		http.Error(w, "无效的订单ID", http.StatusBadRequest)
		return
	}

	var newStatus string
	switch action {
	case "ship":
		newStatus = StatusShipped
	case "receive":
		newStatus = StatusReceived
	default:
		http.Error(w, "无效的操作", http.StatusBadRequest)
		return
	}

	err = UpdateOrderStatus(om.DB, orderID, newStatus, email)
	if err != nil {
		http.Error(w, "更新订单状态失败: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// 重定向回订单列表
	http.Redirect(w, r, "/orders", http.StatusFound)
}

// showOrderList 显示订单列表页面
func (om *OrderManager) showOrderList(w http.ResponseWriter, r *http.Request, email string) {
	orders, err := GetOrdersByUser(om.DB, email)
	if err != nil {
		http.Error(w, "获取订单列表失败: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// 为模板准备数据
	type OrderData struct {
		Order         Order
		StatusText    string
		IsSeller      bool
		CanShip       bool
		CanReceive    bool
		FormattedTime string
	}

	var orderDataList []OrderData
	for _, order := range orders {
		isSeller := order.Seller == email

		// 确定用户可以执行的操作
		canShip := isSeller && order.Status == StatusNotShipped
		canReceive := !isSeller && order.Status == StatusShipped

		orderData := OrderData{
			Order:         order,
			StatusText:    GetStatusText(order.Status),
			IsSeller:      isSeller,
			CanShip:       canShip,
			CanReceive:    canReceive,
			FormattedTime: fmt.Sprintf("%d", order.Time), // 可以扩展为格式化日期
		}

		orderDataList = append(orderDataList, orderData)
	}

	data := struct {
		CurrentUser string
		Orders      []OrderData
	}{
		CurrentUser: email,
		Orders:      orderDataList,
	}

	om.Template.Execute(w, data)
}
