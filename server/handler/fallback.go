package handler

import (
	"bytes"
	"hash/fnv"
	"html/template"
	"math/rand/v2"
	"net/http"
	"strings"
	"sync"
)

var fallbackTmpl = template.Must(template.New("fallback").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{.Title}}</title>
    <style>{{.CSS}}</style>
</head>
<body>
    <header>
        <h1>{{.SiteName}}</h1>
        <p>{{.Tagline}}</p>
    </header>
    <nav>
        <a href="/">{{.NavHome}}</a>
        <a href="/about">{{.NavAbout}}</a>
        <a href="/services">{{.NavServices}}</a>
        <a href="/contact">{{.NavContact}}</a>
    </nav>
    <main>
        <h2>{{.Heading}}</h2>
        {{range .Paragraphs}}<p>{{.}}</p>{{end}}
    </main>
    <footer>
        <p>{{.Footer}}</p>
    </footer>
</body>
</html>`))

// ---------------------------------------------------------------------------
// Theme definitions — each theme has CSS and site-level info.
// Themes are visually distinct: different color palettes, fonts, and layout
// parameters. One theme is randomly selected at startup per deployment.
// ---------------------------------------------------------------------------

type themeDef struct {
	CSS         template.CSS
	SiteName    string
	Tagline     string
	NavHome     string
	NavAbout    string
	NavServices string
	NavContact  string
}

var themes = []themeDef{
	// 1. Ocean Blue — corporate, clean, blue tones
	{
		CSS: `body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;margin:0;padding:0;background:#edf2f7;color:#2d3748;line-height:1.6}
header{background:#1a365d;color:#fff;padding:32px 20px;text-align:center}
header h1{font-size:2rem;margin:0 0 8px 0;font-weight:700}
header p{font-size:1rem;margin:0;opacity:0.85}
nav{background:#2c5282;padding:12px 20px;text-align:center}
nav a{color:#bee3f8;text-decoration:none;margin:0 18px;font-size:.95rem;font-weight:500;transition:color .2s}
nav a:hover{color:#fff}
main{max-width:780px;margin:40px auto;padding:32px;background:#fff;border-radius:8px;box-shadow:0 2px 8px rgba(0,0,0,.08)}
main h2{font-size:1.5rem;margin-top:0;color:#1a365d}
main p{margin:16px 0;font-size:1rem}
footer{text-align:center;padding:24px;color:#a0aec0;font-size:.85rem;border-top:1px solid #e2e8f0}`,
		SiteName:    "Acme Solutions",
		Tagline:     "Innovation delivered with integrity",
		NavHome:     "Home",
		NavAbout:    "About",
		NavServices: "Services",
		NavContact:  "Contact",
	},

	// 2. Forest Green — natural, friendly, rounded
	{
		CSS: `body{font-family:Georgia,"Times New Roman",serif;margin:0;padding:0;background:#f0f7f4;color:#2d3a2e;line-height:1.7}
header{background:#22543d;color:#f0fff4;padding:36px 24px;text-align:center}
header h1{font-size:2.1rem;margin:0 0 6px 0;letter-spacing:-0.5px}
header p{font-size:1.05rem;margin:0;font-style:italic;opacity:0.8}
nav{background:#38a169;padding:14px 20px;text-align:center;border-bottom:3px solid #22543d}
nav a{color:#f0fff4;text-decoration:none;margin:0 20px;font-size:.95rem;text-transform:uppercase;letter-spacing:.5px}
nav a:hover{text-decoration:underline}
main{max-width:760px;margin:36px auto;padding:28px 32px;background:#fff;border-radius:12px;border-left:6px solid #38a169;box-shadow:0 1px 4px rgba(0,0,0,.06)}
main h2{font-size:1.5rem;margin-top:0;color:#22543d}
main p{margin:14px 0;font-size:.98rem}
footer{text-align:center;padding:20px;color:#718096;font-size:.8rem;background:#e2e8e0}`,
		SiteName:    "Greenfield Partners",
		Tagline:     "Rooted in values, growing together",
		NavHome:     "Home",
		NavAbout:    "About Us",
		NavServices: "Solutions",
		NavContact:  "Get in Touch",
	},

	// 3. Dark Modern — tech-forward, dark mode, code-like accents
	{
		CSS: `body{font-family:ui-sans-serif,system-ui,-apple-system,sans-serif;margin:0;padding:0;background:#0d1117;color:#c9d1d9;line-height:1.65}
header{background:#010409;padding:28px 24px;border-bottom:1px solid #21262d;text-align:center}
header h1{font-size:1.8rem;margin:0;color:#58a6ff;font-weight:600}
header p{font-size:.9rem;margin:6px 0 0 0;color:#8b949e}
nav{background:#161b22;padding:10px 20px;text-align:center;border-bottom:1px solid #30363d}
nav a{color:#c9d1d9;text-decoration:none;margin:0 16px;font-size:.88rem}
nav a:hover{color:#58a6ff}
main{max-width:720px;margin:36px auto;padding:28px;background:#161b22;border:1px solid #30363d;border-radius:6px}
main h2{font-size:1.4rem;margin-top:0;color:#f0f6fc}
main p{margin:14px 0;font-size:.92rem;color:#8b949e}
footer{text-align:center;padding:20px;color:#484f58;font-size:.78rem;border-top:1px solid #21262d}`,
		SiteName:    "NexusCode",
		Tagline:     "Engineering the future, one line at a time",
		NavHome:     "Home",
		NavAbout:    "About",
		NavServices: "Platform",
		NavContact:  "Contact",
	},

	// 4. Sunset Amber — warm, traditional, serif-heavy
	{
		CSS: `body{font-family:Cambria,"Hoefler Text",Utopia,"Liberation Serif","Times New Roman",serif;margin:0;padding:0;background:#fef9f0;color:#3e2a1e;line-height:1.7}
header{background:#c05621;color:#fffaf0;padding:38px 20px 28px;text-align:center;border-bottom:4px solid #9c4221}
header h1{font-size:2.2rem;margin:0;font-weight:400;text-shadow:1px 1px 2px rgba(0,0,0,.2)}
header p{font-size:1rem;margin:8px 0 0;opacity:0.9;font-style:italic}
nav{background:#edf2f7;padding:16px 20px;text-align:center}
nav a{color:#9c4221;text-decoration:none;margin:0 22px;font-size:.95rem;font-variant:small-caps}
nav a:hover{color:#c05621;border-bottom:2px solid #c05621}
main{max-width:700px;margin:42px auto;padding:30px 36px;background:#fffaf0;border:1px solid #e2d5c0;box-shadow:0 2px 6px rgba(156,66,33,.08)}
main h2{font-size:1.6rem;margin-top:0;color:#9c4221;font-weight:400}
main p{margin:16px 0;font-size:1rem}
footer{text-align:center;padding:22px;color:#8b6f5e;font-size:.82rem;font-style:italic}`,
		SiteName:    "Crestwood Advisory",
		Tagline:     "Wisdom, trust, and the human touch",
		NavHome:     "Home",
		NavAbout:    "About",
		NavServices: "Expertise",
		NavContact:  "Contact",
	},

	// 5. Minimal Mono — grayscale, clean, modern
	{
		CSS: `body{font-family:"Helvetica Neue",Helvetica,Arial,sans-serif;margin:0;padding:0;background:#fff;color:#333;line-height:1.6}
header{background:transparent;padding:40px 20px 20px;text-align:center;border-bottom:1px solid #eaeaea}
header h1{font-size:1.6rem;margin:0;font-weight:300;color:#111;text-transform:uppercase;letter-spacing:2px}
header p{font-size:.85rem;margin:8px 0 0;color:#999}
nav{padding:16px 20px;text-align:center;border-bottom:1px solid #eaeaea}
nav a{color:#555;text-decoration:none;margin:0 24px;font-size:.8rem;text-transform:uppercase;letter-spacing:1.5px;font-weight:500}
nav a:hover{color:#111}
main{max-width:640px;margin:48px auto;padding:0 24px}
main h2{font-size:1.3rem;margin:0 0 24px;font-weight:400;color:#111}
main p{margin:0 0 20px;font-size:.95rem;color:#555}
footer{text-align:center;padding:28px 20px;color:#bbb;font-size:.75rem;border-top:1px solid #f0f0f0}`,
		SiteName:    "Mode Studio",
		Tagline:     "Crafting clarity through design",
		NavHome:     "Work",
		NavAbout:    "Studio",
		NavServices: "Capabilities",
		NavContact:  "Contact",
	},
}

// ---------------------------------------------------------------------------
// Content pools — realistic, varied text for each page type.
// Content is selected via deterministic hash of the request path,
// so the same URL always gets the same content.
// ---------------------------------------------------------------------------

type pageContent struct {
	Title      string
	Heading    string
	Paragraphs []string
	Footer     string
}

type contentPool map[string][]pageContent

var contentPools = contentPool{
	// ---------- Home ----------
	"home": {
		{
			Title:      "Welcome to Our Site",
			Heading:    "Delivering Results That Matter",
			Paragraphs: []string{"We help organizations navigate complexity and achieve measurable outcomes through strategic thinking and operational excellence.", "Our team brings decades of combined experience across multiple industries. Whether you are launching a new initiative or scaling an existing operation, we have the expertise to guide you."},
			Footer:     "\u00a9 2024 All rights reserved.",
		},
		{
			Title:      "Home \u2014 Trusted Partner for Growth",
			Heading:    "Your Vision, Our Commitment",
			Paragraphs: []string{"Every great achievement starts with a clear vision. We work alongside our clients to turn ambitious ideas into practical, sustainable results.", "From strategy through execution, our collaborative approach ensures alignment at every stage. We measure success by the impact we create together."},
			Footer:     "\u00a9 2024 All rights reserved.",
		},
		{
			Title:      "Leading the Way in Innovation",
			Heading:    "Transforming Challenges into Opportunities",
			Paragraphs: []string{"In a rapidly evolving landscape, staying ahead requires more than just keeping up. Our forward-thinking methodology helps organizations anticipate change and adapt proactively.", "We partner with leaders who are ready to challenge the status quo and build lasting competitive advantage."},
			Footer:     "\u00a9 2024 All rights reserved.",
		},
		{
			Title:      "Excellence in Every Engagement",
			Heading:    "Quality Without Compromise",
			Paragraphs: []string{"For over a decade, organizations have trusted us to deliver solutions that stand the test of time. Our commitment to quality is reflected in everything we do.", "We believe that exceptional outcomes require exceptional partnerships. That is why we invest deeply in understanding your unique context."},
			Footer:     "\u00a9 2024 All rights reserved.",
		},
		{
			Title:      "Welcome to the Future of Business",
			Heading:    "Built for What Is Next",
			Paragraphs: []string{"The pace of change has never been faster. We provide the clarity, tools, and support you need to thrive in an uncertain world.", "Our integrated approach combines deep industry knowledge with cutting-edge practices to deliver sustainable results."},
			Footer:     "\u00a9 2024 All rights reserved.",
		},
	},

	// ---------- About ----------
	"about": {
		{
			Title:      "About Us \u2014 Our Story",
			Heading:    "Who We Are",
			Paragraphs: []string{"Founded in 2010, we have grown from a small team of passionate individuals into a respected organization serving clients across the globe.", "Our mission is simple: deliver exceptional value through expertise, integrity, and relentless focus on our clients\u2019 success."},
			Footer:     "\u00a9 2024 All rights reserved.",
		},
		{
			Title:      "About \u2014 Our Mission and Values",
			Heading:    "Driven by Purpose",
			Paragraphs: []string{"We believe that business can be a force for good. Every engagement is guided by our core values of transparency, collaboration, and continuous improvement.", "Our diverse team brings perspectives from technology, finance, operations, and creative disciplines\u2014united by a shared commitment to making a difference."},
			Footer:     "\u00a9 2024 All rights reserved.",
		},
		{
			Title:      "Our Team",
			Heading:    "Meet the People Behind the Work",
			Paragraphs: []string{"Our strength lies in our people. We have assembled a team of dedicated professionals who are experts in their respective fields.", "From seasoned consultants to emerging talent, everyone on our team shares a passion for solving complex problems and delivering meaningful impact."},
			Footer:     "\u00a9 2024 All rights reserved.",
		},
		{
			Title:      "Company Overview",
			Heading:    "A Legacy of Excellence",
			Paragraphs: []string{"With offices in three major cities and a growing remote workforce, we combine local expertise with global reach.", "Our track record speaks for itself: hundreds of successful engagements, long-term client relationships, and a reputation for delivering on our promises."},
			Footer:     "\u00a9 2024 All rights reserved.",
		},
		{
			Title:      "About Our Approach",
			Heading:    "How We Think",
			Paragraphs: []string{"We take a first-principles approach to every challenge, questioning assumptions and exploring possibilities before committing to a path forward.", "This rigorous, thoughtful methodology has earned us the trust of some of the most demanding organizations in the world."},
			Footer:     "\u00a9 2024 All rights reserved.",
		},
	},

	// ---------- Contact ----------
	"contact": {
		{
			Title:      "Contact Us",
			Heading:    "Get in Touch",
			Paragraphs: []string{"We would love to hear from you. Whether you have a question about our services, want to explore a partnership, or simply want to learn more, our team is here to help.", "You can reach us by phone at +1 (555) 123-4567, by email at info@example.com, or by visiting our office at 123 Business Avenue, Suite 400, New York, NY 10001."},
			Footer:     "\u00a9 2024 All rights reserved.",
		},
		{
			Title:      "Contact \u2014 Let\u2019s Talk",
			Heading:    "We Are Ready to Help",
			Paragraphs: []string{"Our team is available Monday through Friday, 9 AM to 6 PM Eastern Time. We strive to respond to all inquiries within one business day.", "For general inquiries: contact@example.com. For support: support@example.com. Phone: +1 (555) 987-6543."},
			Footer:     "\u00a9 2024 All rights reserved.",
		},
		{
			Title:      "Find Us",
			Heading:    "Our Locations",
			Paragraphs: []string{"Headquarters: 456 Park Avenue, 12th Floor, San Francisco, CA 94102. Satellite office: 789 Innovation Drive, Austin, TX 78701.", "We also offer virtual consultations for clients around the world. Schedule a call at your convenience."},
			Footer:     "\u00a9 2024 All rights reserved.",
		},
		{
			Title:      "Contact Information",
			Heading:    "Reach Out Anytime",
			Paragraphs: []string{"We value open communication and are always happy to discuss how we can support your goals.", "Email: hello@example.com | Phone: +1 (555) 456-7890 | Follow us on LinkedIn and Twitter for the latest updates."},
			Footer:     "\u00a9 2024 All rights reserved.",
		},
		{
			Title:      "Support Center",
			Heading:    "How Can We Assist You?",
			Paragraphs: []string{"For existing clients, our support portal provides a knowledge base, ticket submission, and live chat during business hours.", "Not a client yet? Our sales team can walk you through our offerings and help identify the right solution for your needs."},
			Footer:     "\u00a9 2024 All rights reserved.",
		},
	},

	// ---------- Services ----------
	"services": {
		{
			Title:      "Our Services",
			Heading:    "What We Offer",
			Paragraphs: []string{"We provide a comprehensive suite of services designed to help organizations thrive in a competitive environment. Our core offerings include strategic consulting, technology implementation, and operational optimization.", "Each engagement is tailored to the specific needs of our clients. We do not believe in one-size-fits-all solutions."},
			Footer:     "\u00a9 2024 All rights reserved.",
		},
		{
			Title:      "Products and Solutions",
			Heading:    "Tools That Empower",
			Paragraphs: []string{"Our product portfolio spans data analytics, cloud infrastructure, workflow automation, and customer engagement platforms.", "Built on modern architecture with security and scalability at the core, our solutions integrate seamlessly with your existing technology stack."},
			Footer:     "\u00a9 2024 All rights reserved.",
		},
		{
			Title:      "Pricing",
			Heading:    "Transparent and Flexible",
			Paragraphs: []string{"We offer flexible pricing models designed to align with your budget and business needs. From project-based engagements to ongoing retainers, we work with you to find the right arrangement.", "Contact our team for a customized quote based on your specific requirements and scope."},
			Footer:     "\u00a9 2024 All rights reserved.",
		},
		{
			Title:      "Consulting Services",
			Heading:    "Expert Guidance, Tangible Results",
			Paragraphs: []string{"Our consulting practice helps organizations address their most pressing challenges: growth strategy, digital transformation, organizational design, and operational efficiency.", "We bring an outside perspective grounded in data, experience, and rigorous analysis."},
			Footer:     "\u00a9 2024 All rights reserved.",
		},
		{
			Title:      "Managed Services",
			Heading:    "Focus on Your Core Business",
			Paragraphs: []string{"Let us handle the complexity. Our managed services team provides ongoing support, monitoring, and optimization for your critical systems and processes.", "With 24/7 coverage and proactive issue resolution, you can focus on what matters most: serving your customers and growing your business."},
			Footer:     "\u00a9 2024 All rights reserved.",
		},
	},

	// ---------- Blog / News ----------
	"blog": {
		{
			Title:      "Industry Insights and Trends",
			Heading:    "What Is Shaping the Landscape",
			Paragraphs: []string{"The industry is undergoing significant transformation driven by advances in artificial intelligence, shifting regulatory frameworks, and evolving customer expectations.", "In this article, we explore the key trends that leaders should be paying attention to in the coming year."},
			Footer:     "\u00a9 2024 All rights reserved.",
		},
		{
			Title:      "Latest News and Announcements",
			Heading:    "What\u2019s New",
			Paragraphs: []string{"We are excited to share recent developments, including new partnerships, expanded capabilities, and recognition from industry analysts.", "Stay tuned for more updates as we continue to grow and evolve."},
			Footer:     "\u00a9 2024 All rights reserved.",
		},
		{
			Title:      "Best Practices Guide",
			Heading:    "A Practical Framework for Success",
			Paragraphs: []string{"After years of working with organizations of all sizes, we have distilled our learning into a practical guide for navigating complex initiatives.", "This guide covers planning, execution, measurement, and continuous improvement."},
			Footer:     "\u00a9 2024 All rights reserved.",
		},
		{
			Title:      "Case Study: Driving Operational Excellence",
			Heading:    "How One Organization Achieved a 40% Efficiency Gain",
			Paragraphs: []string{"We recently partnered with a mid-size manufacturing company to overhaul their supply chain operations. The results exceeded expectations.", "Read the full case study to learn about the approach, the challenges, and the lessons we learned along the way."},
			Footer:     "\u00a9 2024 All rights reserved.",
		},
		{
			Title:      "Technology Radar",
			Heading:    "Tools and Platforms Worth Watching",
			Paragraphs: []string{"Our team regularly evaluates emerging technologies to help clients make informed decisions about their technology investments.", "Here are the tools and platforms that have caught our attention this quarter."},
			Footer:     "\u00a9 2024 All rights reserved.",
		},
	},

	// ---------- Generic (any other path) ----------
	"generic": {
		{
			Title:      "\u00a0",
			Heading:    "Page Not Found",
			Paragraphs: []string{"The page you are looking for might have been moved or is temporarily unavailable. Please check the URL and try again, or navigate back to the homepage."},
			Footer:     "\u00a9 2024 All rights reserved.",
		},
		{
			Title:      "Resource Center",
			Heading:    "Explore Our Resources",
			Paragraphs: []string{"Our resource center provides a wealth of information including whitepapers, webinars, case studies, and industry reports.", "Browse by topic or use the search function to find what you need."},
			Footer:     "\u00a9 2024 All rights reserved.",
		},
		{
			Title:      "Knowledge Base",
			Heading:    "Find Answers Fast",
			Paragraphs: []string{"Our knowledge base contains hundreds of articles covering common questions, troubleshooting guides, and best practices.", "If you cannot find what you are looking for, our support team is ready to assist."},
			Footer:     "\u00a9 2024 All rights reserved.",
		},
		{
			Title:      "Documentation",
			Heading:    "Technical Documentation",
			Paragraphs: []string{"Comprehensive documentation for our products and services, including API references, integration guides, and release notes.", "Documentation is updated regularly to reflect the latest features and improvements."},
			Footer:     "\u00a9 2024 All rights reserved.",
		},
		{
			Title:      "FAQ",
			Heading:    "Frequently Asked Questions",
			Paragraphs: []string{"We have compiled answers to the most common questions we receive from clients and partners.", "If your question is not addressed here, please do not hesitate to contact us directly."},
			Footer:     "\u00a9 2024 All rights reserved.",
		},
	},
}

// ---------------------------------------------------------------------------
// Types for rendering
// ---------------------------------------------------------------------------

type renderData struct {
	CSS         template.CSS
	SiteName    string
	Tagline     string
	NavHome     string
	NavAbout    string
	NavServices string
	NavContact  string
	Title       string
	Heading     string
	Paragraphs  []string
	Footer      string
}

// ---------------------------------------------------------------------------
// Global state
// ---------------------------------------------------------------------------

var (
	initOnce       sync.Once
	selectedTheme  themeDef
	customFallback []byte
	htmlCache      sync.Map // path string → []byte
)

// SetFallbackHTML overrides the built-in fallback system with custom HTML.
// Must be called before the server starts accepting requests.
func SetFallbackHTML(html []byte) {
	if len(html) == 0 {
		return
	}
	customFallback = make([]byte, len(html))
	copy(customFallback, html)
}

// ServeFallback writes a fallback HTML page to the response.
// If custom HTML was set via SetFallbackHTML, it is used for all paths.
// Otherwise a themed, path-aware page is rendered.
func ServeFallback(w http.ResponseWriter, r *http.Request) {
	initOnce.Do(func() {
		selectedTheme = themes[rand.IntN(len(themes))]
	})

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Server", "nginx")
	w.WriteHeader(http.StatusOK)

	if len(customFallback) > 0 {
		w.Write(customFallback) //nolint:errcheck
		return
	}

	w.Write(getOrRenderHTML(r.URL.Path)) //nolint:errcheck
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

func getOrRenderHTML(path string) []byte {
	if cached, ok := htmlCache.Load(path); ok {
		return cached.([]byte)
	}

	html := renderHTML(path)
	htmlCache.Store(path, html)
	return html
}

func renderHTML(path string) []byte {
	pageType := detectPageType(path)
	pool := contentPools[pageType]
	idx := hashIndex(path, len(pool))
	content := pool[idx]

	data := renderData{
		CSS:         selectedTheme.CSS,
		SiteName:    selectedTheme.SiteName,
		Tagline:     selectedTheme.Tagline,
		NavHome:     selectedTheme.NavHome,
		NavAbout:    selectedTheme.NavAbout,
		NavServices: selectedTheme.NavServices,
		NavContact:  selectedTheme.NavContact,
		Title:       resolveTitle(content.Title, selectedTheme.SiteName),
		Heading:     content.Heading,
		Paragraphs:  content.Paragraphs,
		Footer:      content.Footer,
	}

	var buf bytes.Buffer
	if err := fallbackTmpl.Execute(&buf, data); err != nil {
		return []byte("Internal Server Error")
	}
	return buf.Bytes()
}

func detectPageType(path string) string {
	path = strings.ToLower(strings.Trim(path, "/"))
	switch {
	case path == "":
		return "home"
	case path == "about", strings.HasPrefix(path, "about/"):
		return "about"
	case path == "contact" || path == "support" || strings.HasPrefix(path, "contact/"),
		path == "help":
		return "contact"
	case path == "services" || path == "products" || path == "solutions" ||
		path == "pricing", strings.HasPrefix(path, "services/"),
		strings.HasPrefix(path, "products/"), strings.HasPrefix(path, "solutions/"):
		return "services"
	case path == "blog" || path == "news" || path == "articles" ||
		strings.HasPrefix(path, "blog/") || strings.HasPrefix(path, "news/") ||
		strings.HasPrefix(path, "articles/"):
		return "blog"
	default:
		return "generic"
	}
}

func hashIndex(input string, n int) int {
	h := fnv.New32a()
	h.Write([]byte(input))
	return int(h.Sum32()) % n
}

// resolveTitle returns the page title. If the content title is empty or just a
// space, the site name is used as a fallback.
func resolveTitle(title, siteName string) string {
	title = strings.TrimSpace(title)
	if title == "" {
		return siteName
	}
	return title
}
