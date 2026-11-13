package scope

import "testing"

func TestEmptyScopeFailsClosed(t *testing.T) {
	if _, err := Compile(&File{}, "inline"); err == nil {
		t.Fatal("empty scope must be rejected")
	}
	if _, err := Compile(&File{Networks: []string{}, Hosts: []string{}}, "inline"); err == nil {
		t.Fatal("explicitly empty scope must be rejected")
	}
}

func TestAllowsInsideAndOutsideNetwork(t *testing.T) {
	s, err := Compile(&File{Networks: []string{"10.0.0.0/30"}}, "inline")
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if !s.Allows("10.0.0.1") {
		t.Fatal("inside host refused")
	}
	if s.Allows("10.0.0.9") {
		t.Fatal("outside host allowed")
	}
	if s.Allows("") {
		t.Fatal("empty host allowed")
	}
}

func TestHostEntryIsExact(t *testing.T) {
	s, err := Compile(&File{Hosts: []string{"db.internal"}}, "inline")
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if !s.Allows("db.internal") {
		t.Fatal("listed host refused")
	}
	if s.Allows("other.internal") {
		t.Fatal("unlisted host allowed")
	}
}

func TestBadCIDRRejected(t *testing.T) {
	if _, err := Compile(&File{Networks: []string{"10.0.0.0/99"}}, "inline"); err == nil {
		t.Fatal("bad CIDR accepted")
	}
}

func TestPortsDefaultAndSort(t *testing.T) {
	s, err := Compile(&File{Hosts: []string{"a"}}, "inline")
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	ports := s.Ports()
	if len(ports) != len(DefaultPorts) {
		t.Fatalf("expected default ports, got %v", ports)
	}
	for i := 1; i < len(ports); i++ {
		if ports[i-1] > ports[i] {
			t.Fatalf("ports not sorted: %v", ports)
		}
	}
}

func TestInvalidPortRejected(t *testing.T) {
	if _, err := Compile(&File{Hosts: []string{"a"}, Ports: []int{0}}, "inline"); err == nil {
		t.Fatal("port 0 accepted")
	}
	if _, err := Compile(&File{Hosts: []string{"a"}, Ports: []int{70000}}, "inline"); err == nil {
		t.Fatal("port 70000 accepted")
	}
}
