package main

type Device struct {
	Name        string
	Role        string // ? *
	Description string
	Tags        []string
	Type        string // ? *
	Airflow     string
	Serial      string
	AssetTag    string
	Site        string // ? Req *
	Location    string
	Rack        string
	RackFace    string
	Position    string
	Latitude    string
	Longitude   string
	Status      string
	Platform    string
	ConfigTemp  string
	Cluster     string
	TenantGrp   string
	Tenant      string
	ViChassis   string
}
