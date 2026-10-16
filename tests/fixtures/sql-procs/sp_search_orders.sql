CREATE PROCEDURE sp_search_orders @Customer NVARCHAR(100), @Sort NVARCHAR(50)
AS
BEGIN
  DECLARE @sql NVARCHAR(4000)
  SET @sql = 'SELECT * FROM Orders WHERE Customer = ''' + @Customer + ''' ORDER BY ' + @Sort -- LSA-EXPECT:SQLI
  EXEC(@sql) -- LSA-EXPECT:SQLI
END
