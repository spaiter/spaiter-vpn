package ui

import "testing"

func TestNotifyTextKeepsLineBreaksAndDropsTheCommand(t *testing.T) {
	got := notifyText("/notify Вышла версия 0.1.7.\nОбновитесь.")
	if got != "Вышла версия 0.1.7.\nОбновитесь." {
		t.Fatalf("got %q", got)
	}
	if notifyText("/notify") != "" || notifyText("/notify   ") != "" {
		t.Fatal("a bare command must yield no text")
	}
}
