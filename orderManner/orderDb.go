package orderManner

import (
	"database/sql"
	"errors"
	"time"
)

// Order 订单结构体
type Order struct {
	ID       int64  `json:"id"`
	Seller   string `json:"seller"`
	Buyer    string `json:"buyer"`
	Price    int    `json:"price"`
	PostLink string `json:"post_link"`
	Time     int64  `json:"time"`
	Status   string `json:"status"`
}

// OrderStatus 定义订单状态常量
const (
	StatusNotShipped = "A" // 没有发货(默认)
	StatusShipped    = "B" // 已经发货
	StatusReceived   = "C" // 确定签收
)

// GetStatusText 获取状态对应的文本描述
func GetStatusText(status string) string {
	switch status {
	case StatusNotShipped:
		return "未发货"
	case StatusShipped:
		return "已发货"
	case StatusReceived:
		return "已签收"
	default:
		return "未知状态"
	}
}

// CreateOrder 创建新订单
func CreateOrder(db *sql.DB, seller, buyer string, price int, postLink string) (int64, error) {
	if seller == "" || buyer == "" || price <= 0 || postLink == "" {
		return 0, errors.New("订单参数不完整")
	}

	result, err := db.Exec(
		"INSERT INTO orders (seller, buyer, price, post_link, time, status) VALUES (?, ?, ?, ?, ?, ?)",
		seller, buyer, price, postLink, time.Now().Unix(), StatusNotShipped,
	)
	if err != nil {
		return 0, err
	}

	return result.LastInsertId()
}

// GetOrdersByUser 获取用户相关的订单（作为卖家或买家）
func GetOrdersByUser(db *sql.DB, email string) ([]Order, error) {
	rows, err := db.Query(
		"SELECT id, seller, buyer, price, post_link, time, status FROM orders WHERE seller = ? OR buyer = ? ORDER BY time DESC",
		email, email,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var orders []Order
	for rows.Next() {
		var o Order
		if err := rows.Scan(&o.ID, &o.Seller, &o.Buyer, &o.Price, &o.PostLink, &o.Time, &o.Status); err != nil {
			return nil, err
		}
		orders = append(orders, o)
	}

	return orders, nil
}

// GetOrderByDetails 通过详细信息获取订单
func GetOrderByDetails(db *sql.DB, user, postLink string, timestamp int64) (*Order, error) {
	var order Order
	err := db.QueryRow(
		"SELECT id, seller, buyer, price, post_link, time, status FROM orders WHERE (seller = ? OR buyer = ?) AND post_link = ? AND time = ?",
		user, user, postLink, timestamp,
	).Scan(&order.ID, &order.Seller, &order.Buyer, &order.Price, &order.PostLink, &order.Time, &order.Status)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.New("订单不存在")
		}
		return nil, err
	}

	return &order, nil
}

// UpdateOrderStatus 更新订单状态
func UpdateOrderStatus(db *sql.DB, orderID int64, newStatus string, email string) error {
	// 检查状态转换是否合法
	if newStatus != StatusNotShipped && newStatus != StatusShipped && newStatus != StatusReceived {
		return errors.New("无效的订单状态")
	}

	// 检查用户是否有权限更新状态
	var order Order
	err := db.QueryRow(
		"SELECT seller, buyer, status FROM orders WHERE id = ?", orderID,
	).Scan(&order.Seller, &order.Buyer, &order.Status)

	if err != nil {
		return err
	}

	// 卖家只能将订单状态从A更新到B
	// 买家只能将订单状态从B更新到C
	validUpdate := false
	if email == order.Seller && order.Status == StatusNotShipped && newStatus == StatusShipped {
		validUpdate = true
	} else if email == order.Buyer && order.Status == StatusShipped && newStatus == StatusReceived {
		validUpdate = true
	}

	if !validUpdate {
		return errors.New("无权更新此订单状态")
	}

	_, err = db.Exec("UPDATE orders SET status = ? WHERE id = ?", newStatus, orderID)
	return err
}

// GetOrderByID 通过ID获取订单
func GetOrderByID(db *sql.DB, orderID int64) (*Order, error) {
	var order Order
	err := db.QueryRow(
		"SELECT id, seller, buyer, price, post_link, time, status FROM orders WHERE id = ?",
		orderID,
	).Scan(&order.ID, &order.Seller, &order.Buyer, &order.Price, &order.PostLink, &order.Time, &order.Status)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.New("订单不存在")
		}
		return nil, err
	}

	return &order, nil
}
