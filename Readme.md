# Trying to implement the JWT standart 

Example
```
string token = Token.New(new Dictionary<string, string>() { 
                    {"name", "name1"},
                    {"id", "100"}
                }, 30);

var tInfo = Token.Parse(token);
```