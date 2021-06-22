package cwe

func Set(id string, weakness *Weakness) {
	data[id] = weakness
}

func GetOrEmpty(id string) *Weakness {
	weakness, ok := data[id]
	if ok && weakness != nil {
		return weakness
	}

	return &Weakness{
		ID:          "NONE",
		Name:        "NONE",
		Description: "NONE",
	}
}
