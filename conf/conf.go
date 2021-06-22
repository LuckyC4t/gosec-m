package conf

var config = make(map[string]interface{})

func Get(key string) interface{} {
	if value, has := config[key]; has {
		return value
	}
	return nil
}

func Set(key string, value interface{}) {
	config[key] = value
}
