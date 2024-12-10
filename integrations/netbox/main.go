type Device struct {
	Name        string
	Role        string // ? *
	Description string
	Tags        []string
	Type        string // ? *
	Airflow     string
	Serial      string
	AssetTag    string
	Site        site // ? Req *
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
	ViChassis   ViChassis
}

type ViChassis struct {
	Position string
	Priority string
}

// ------------------------------ SITE MODULES
type Site struct {
	Name        string
	Slug        string
	Status      string
	Region      Region
	Group       string
	Facility    string
	ASNs        []int
	TZ          string
	Description string
	Tags        []string
	TenantGrp   string
	Tenant      string
	PhyAddr     string
	ShipAddr    string
	Latitude    string
	Longitude   string
	Comments    string
}

type SiteGroup struct {
	Parent      string
	Name        string
	Slug        string
	Description string
	Tags        []string
}

type Region struct {
	Parent      string
	Name        string
	Slug        string
	Description string
	Tags        []string
}

type Location struct {
	Site        site
	Parent      string
	Name        string
	Slug        string
	Status      string
	Facility    string
	Description string
	Tags        []string
	TenantGrp   string
	Tenant      string
}

// ------------------------------ TENANT MODULES
type Tenant struct {
	Name        string
	Slug        string
	Group       string
	Description string
	Tags        []string
	Comments    string
}
type TenantGroup struct {
	Parent      string
	Name        string
	Slug        string
	Description string
	Tags        []string
}

// ----------------------------- CONTACTS MODULES
type Contact struct {
	Group       string
	Name        string
	Title       string
	Phone       string
	Email       string
	Address     string
	Link        string
	Description string
	Tags        []string
	Comments    string
}
type ContactGroup struct {
	Parent      string
	name        string
	Slug        string
	Description string
	Tags        []string
}
type ContactRole struct {
	Name        string
	Slug        string
	Description string
	Tags        []string
}

// ----------------------------- RACK MODULES
