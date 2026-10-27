# Go Knowledge Profile (Gin, Fiber, Echo, Chi, GORM, database/sql)

## Stack Identification
- **Markers:** `go.mod`, `go.sum`, `main.go`, `*.go`.
- **Frameworks:**
  - `gin`: `github.com/gin-gonic/gin`
  - `fiber`: `github.com/gofiber/fiber/v2`
  - `echo`: `github.com/labstack/echo/v4`
  - `chi`: `github.com/go-chi/chi/v5`
  - `net/http`: `http.HandleFunc`, `http.ListenAndServe`
- **Data Access:**
  - `gorm`: `gorm.io/gorm`
  - `database/sql`: `sql.Open`, `db.Query`, `db.Exec`
  - `pgx`: `github.com/jackc/pgx/v5`

## BOLA / IDOR Patterns
- **Vulnerable:** Handlers parsing IDs from URL parameters without checking user/tenant identity:
  ```go
  // Vulnerable Gin handler
  func GetOrder(c *gin.Context) {
      id := c.Param("id")
      var order Order
      db.First(&order, id) // No tenant or ownership verification
      c.JSON(200, order)
  }
  ```
- **Protected:** Handlers extracting authenticated user from context and scoping query by tenant/owner:
  ```go
  // Protected with ownership check
  func GetOrder(c *gin.Context) {
      id := c.Param("id")
      userID := c.GetString("user_id")
      var order Order
      if err := db.Where("id = ? AND owner_id = ?", id, userID).First(&order).Error; err != nil {
          c.JSON(404, gin.H{"error": "Order not found"}) // Invariant: 404
          return
      }
      c.JSON(200, order)
  }
  ```

## SQL Injection Patterns
- **Safe:** Parameterized queries:
  - `db.Where("username = ?", username).Find(&users)`
  - `db.Query("SELECT * FROM users WHERE id = $1", id)`
- **Vulnerable:** String concatenation or `fmt.Sprintf` into raw SQL:
  - `db.Raw(fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", name))`
  - `db.Exec("DELETE FROM items WHERE id = " + id)`
