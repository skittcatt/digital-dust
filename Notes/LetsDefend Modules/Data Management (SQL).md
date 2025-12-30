___
## What is Data?
It refers to a collection of (raw) pieces of information. Can be in many different forms, such as text, numbers, audio, images, video and other forms.

---
### Data Models

**Different Types:**
- Relational
	- Most popular model.
	- Structured with tables that have columns and rows.
		- Each column has a unique name and represents "attributes"
		- Each row represents a single/unique entity
	- It is a secure data model that ensures protection of data integrity.
	- Not suitable for large databases.
- Semi-structured
	- Uses tags and elements to group and hold data.
	- Examples of uses of this data model include:
		- E-mail
		- HTML
		- binary exe files
		- TCP/IP packets
		- Web pages
		- XML files
	- Items in a group can have different sizes and types.
	- Allows for different data types to be together.
	- Storage is more difficult due to the fact that it does not have a fixed schema.
	- Data security may not be as robust compared to other models.
- Key-Value
	- Used in non-relational databases.
	- Has keys and values:
		- A key is associated with only one value.
		- A value can be any entity.
	- Easy to use and operate, operations can be implemented easily.
	- Supports different data types.
	- Doesn't use the query language so transmitting queries from one database to another is not possible.
	- Cannot query the database without a key.
- Graph Based
	- Works by establishing relationships between data.
		- Each component is a 'node'.
		- Relationships between nodes is a 'link'.
		- 'Edges' are the representation of the relationship between nodes.
		- Information about the nodes are called 'properties'.
	-  User-friendly structure.
	- No standard query language as it is based on the platform used.
- Object-orientated
	- A combination of object-orientated programming and the relational data model.
	- Easy-to-understand structure.
	- Codes can be reused by inheritance.
	- Fairly new and not developed properly.

---
### Commands Examples
*Please note that some of these functions will only work for PostgreSQL*

| Command                    | Function                                                                   | Example                                                                                                                                                                        |
| -------------------------- | -------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **SELECT**                 | Select and view data from the database                                     | Display all data in the 'region' table:<br>`SELECT * FROM region;`                                                                                                             |
| **FROM**                   | Specifies which table to gather data from                                  | View above                                                                                                                                                                     |
| **DISTINCT**               | No data is repeated twice                                                  | Display unique discount amounts from the 'order_details' table<br>`SELECT DISTINCT discount FROM order_details;`                                                               |
| **WHERE**                  | Perform conditional queries                                                | Display all items from the 'categories' table which has an ID of 8<br>`SELECT * FROM categories WHERE category_id=8;`                                                          |
| **AND**                    | When more than one condition must be met                                   | Display data from the 'order_details' table that has an order ID of 10294 and quantity of 15<br>`SELECT * FROM order_details WHERE order_id=10294 AND quantity=15;`            |
| **OR**                     | When at least one of the conditions must be met                            | Display data from 'order_details' where either the ID is 10294 or quantity is 90<br>`SELECT * FROM order_details WHERE order_id=10294 OR quantity=90;`                         |
| **NOT**                    | When omitting certain conditions from the output                           | Display all rows from the 'region' table except for ID 1<br>`SELECT * FROM region WHERE NOT region_id=1;`                                                                      |
| **ORDER BY**               | For sorting operations where you want to order by certain columns          | Display all rows from region in order of largest to smallest ID<br>`SELECT * FROM region ORDER BY region_id DESC;`                                                             |
| **INSERT INTO ___ VALUE ** | Used to add records to a table                                             | Add a record with an ID of 1 and type of 'Malware' to the alert table<br>`INSERT INTO alert(alertid, alerttype) VALUES (1, 'Malware');`                                        |
| **NULL**                   | When there is no data in a particular column of a row                      | Display all alert ID's without an alert type<br>`SELECT * FROM alert WHERE alerttype IS NULL;`                                                                                 |
| **UPDATE __ SET**          | Updates existing data in a row                                             | Update the alert type of alert ID 3 to 'Web Attack'<br>`UPDATE alert SET alerttype='Web Attack' WHERE alertid=3;`                                                              |
| **DELETE**                 | Deletes data or a record from a table                                      | Delete the record of alert ID 2<br>`DELETE FROM alert WHERE alertid=2;`                                                                                                        |
| **LIMIT**                  | Limits the amount of lines displayed from a query                          | Only display the first 5 of 2155 lines of the table 'order_details'<br>`SELECT * FROM order_details LIMIT 5;`                                                                  |
| **MIN() & MAX()**          | Returns the minimum or maximum (respectively) value from a table/column    | Display the minimum then the maximum unit price from the 'order_details' table<br>`SELECT MIN(unit_price) FROM order_details;`<br>`SELECT MAX(unit_price) FROM order_details;` |
| **COUNT()**                | Returns the amount of lines that would appear from a query                 | Display the amount of ID's from the 'region' table<br>`SELECT count(region_id) FROM region;`                                                                                   |
| **AVG()**                  | Returns the average num value of the respective column                     | Display the average ID number of alertID from the 'alert' table<br>`SELECT AVG(alertid) FROM alert;`                                                                           |
| **SUM()**                  | Returns the numeric sum of the respective column                           | Display the total of all the alert ID's from the 'alert' table<br>`SELECT SUM(alertid) FROM alert;`                                                                            |
| **UNION**                  | Combines the results of multiple queries into a single output              | Combine the alerts from 'alert' and 'alert2' into a single output<br>`SELECT * FROM alert UNION SELECT * FROM alert2;`                                                         |
| **SUBSTR()**               | Cuts a certain character group from a certain column to a specified length | Display only the first 3 characters of the attributes from the 'alerttype' column in the 'alert' table<br>`SELECT substr(alerttype, 1, 3) FROM alert;`                         |
| **DROP DATABASE**          | Deletes an entire database                                                 | Remove the 'temp_database' database<br>`DROP DATABASE temp_database;`                                                                                                          |
| **SELECT version()**       | Provides the postgresql version                                            | -                                                                                                                                                                              |
| **/* */**                  | Inserts comments into a query without disrupting the query                 | `SELECT * FROM /* This is a comment. */ alert;`                                                                                                                                |

### Operators
| Operator           | Description                                                                  |
| ------------------ | :--------------------------------------------------------------------------- |
| =                  | Equal                                                                        |
| >                  | Greater than                                                                 |
| <                  | Lesser than                                                                  |
| >=                 | Greater than or equal                                                        |
| <=                 | Lesser than or equal                                                         |
| <> / !=            | Not equal                                                                    |
| BETWEEN            | Between a certain range                                                      |
| LIKE               | Search for a pattern                                                         |
| IN ( ____ , ____ ) | To specify multiple possible values for a column, can be used in place of OR |
| %                  | Wildcard symbol                                                              |
___
