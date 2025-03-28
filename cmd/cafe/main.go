package main

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/cloudflare/cloudflare-go"
	"github.com/google/go-jsonnet"

	token "github.com/namcxn/cafe/lib"
)

func main() {
	flag.Usage = usage
	flag.Parse()

	token, err := token.GetCloudflareToken()
	if err != nil {
		log.Fatal("token error:", err)
	}

	api, err := cloudflare.NewWithAPIToken(token)
	if err != nil {
		log.Fatal(err)
	}

	ctx := context.Background()

	zones, err := api.ListZones(ctx)
	if err != nil {
		log.Fatalf("get zones: %s", err)
	}

	zoneIds := make(map[string]string, 0)

	cfRecords := make([]cloudflare.DNSRecord, 0)

	for _, zone := range zones {
		zoneIds[zone.Name] = zone.ID

		records, _, err := api.ListDNSRecords(ctx, cloudflare.ZoneIdentifier(zone.ID), cloudflare.ListDNSRecordsParams{})
		if err != nil {
			log.Fatalf("get record for zone %s: %s", zone.Name, err)
		}

		cfRecords = append(cfRecords, records...) // Get All Records
	}

	vm := jsonnet.MakeVM()

	dfRecords := make([]cloudflare.DNSRecord, 0)

	zoneRoot := os.Getenv("ZONES_DIR")
	if zoneRoot == "" {
		zoneRoot = "./zones"
	}
	err = filepath.Walk(zoneRoot, func(path string, info fs.FileInfo, err error) error {
		if info.IsDir() {
			return nil
		}
		if strings.HasSuffix(path, ".jsonnet") {
			jsonData, err := vm.EvaluateFile(path)
			if err != nil {
				log.Printf("Failed to evaluate Jsonnet file %s: %v", path, err)
				return err
			}

			records := make([]cloudflare.DNSRecord, 0)

			err = json.Unmarshal([]byte(jsonData), &records)
			if err != nil {
				log.Printf("Error walking through zone directory: %v", err)
				return err
			}

			for _, record := range records {
				zoneName := getZoneName(record)
				if _, ok := zoneIds[zoneName]; !ok {
					fmt.Printf("\nError at %s\nZone `%s` is not managed by cafe! Is it corrected?\n", path, zoneName)
					os.Exit(1)
				}
			}

			dfRecords = append(dfRecords, records...)

		}

		return nil
	})
	if err != nil {
		log.Fatalf("walk dir error %s", err)
	}

	cnames := SetOf[string]()

	managed := SetOf[string]()
	stored := SetOf[string]()

	deleting := make([]cloudflare.DNSRecord, 0)
	adding := make([]cloudflare.DNSRecord, 0)

	defined := SetOf[string]()
	deprecate := SetOf[string]()

	for _, record := range dfRecords {
		managed.Add(nt(record))
	}

	for _, record := range dfRecords {
		if record.Type == "CNAME" {
			if cnames.Has(record.Name) {
				log.Fatalf("ERROR: cname is duplicated: %s", record.Name)
			}
			cnames.Add(record.Name)
			defined.Add(hash(record))
		} else if record.Type == "DEPRECATED" {
			deprecate.Add(record.Name)
		} else {
			defined.Add(hash(record))
		}
	}

	for _, record := range cfRecords {
		if managed.Has(nt(record)) {
			h := hash(record)
			if !defined.Has(h) || deprecate.Has(record.Name) {
				deleting = append(deleting, record)
			}
			stored.Add(h)
		}
	}

	for _, record := range dfRecords {
		if record.Type != "DEPRECATED" {
			if !stored.Has(hash(record)) {
				adding = append(adding, record)
			}
		}
	}

	if len(deleting) > 0 {
		fmt.Printf("Those records will be deleted:\n")

		// Headers
		headers := []string{"ZONE", "TYPE", "TTL", "NAME", "CONTENT", "PROXY"}

		// Collect all rows as strings
		rows := [][]string{}
		for _, record := range deleting {
			row := []string{
				getZoneName(record),
				record.Type,
				fmt.Sprintf("%d", record.TTL),
				record.Name,
				record.Content,
				fmt.Sprintf("%v", *record.Proxied),
			}
			rows = append(rows, row)
		}

		// Calculate column widths
		columnWidths := make([]int, len(headers))
		for i, header := range headers {
			columnWidths[i] = len(header)
		}
		for _, row := range rows {
			for i, cell := range row {
				if len(cell) > columnWidths[i] {
					columnWidths[i] = len(cell)
				}
			}
		}

		// Create format string dynamically
		formatParts := make([]string, len(columnWidths))
		for i, width := range columnWidths {
			formatParts[i] = fmt.Sprintf("%%-%ds", width+2)
		}
		format := strings.Join(formatParts, "")

		// Print headers
		fmt.Printf(format+"\n", toInterfaceSlice(headers)...)

		// Print rows
		for _, row := range rows {
			fmt.Printf(format+"\n", toInterfaceSlice(row)...)
		}
	}

	if len(adding) > 0 {
		fmt.Printf("\nThose records will be created:\n")

		// Headers
		headers := []string{"ZONE", "TYPE", "TTL", "NAME", "CONTENT", "PROXY"}

		// Collect all rows as strings
		rows := [][]string{}
		for _, record := range adding {
			row := []string{
				getZoneName(record),
				record.Type,
				fmt.Sprintf("%d", record.TTL),
				record.Name,
				record.Content,
				fmt.Sprintf("%v", *record.Proxied),
			}
			rows = append(rows, row)
		}

		// Calculate column widths
		columnWidths := make([]int, len(headers))
		for i, header := range headers {
			columnWidths[i] = len(header)
		}
		for _, row := range rows {
			for i, cell := range row {
				if len(cell) > columnWidths[i] {
					columnWidths[i] = len(cell)
				}
			}
		}

		// Create format string dynamically
		formatParts := make([]string, len(columnWidths))
		for i, width := range columnWidths {
			formatParts[i] = fmt.Sprintf("%%-%ds", width+2)
		}
		format := strings.Join(formatParts, "")

		// Print headers
		fmt.Printf(format+"\n", toInterfaceSlice(headers)...)

		// Print rows
		for _, row := range rows {
			fmt.Printf(format+"\n", toInterfaceSlice(row)...)
		}
	}

	if os.Getenv("CAFE_CONFIRM") == "yes" {

		if len(deleting) > 0 || len(adding) > 0 {
			fmt.Printf("\nDo update records...\n\n")
		}

		for _, record := range deleting {
			fmt.Printf("deleting %-20s%-8s%-6d%-40s%s...\n", getZoneName(record), record.Type, record.TTL, record.Name, record.Content)
			err := api.DeleteDNSRecord(ctx, cloudflare.ZoneIdentifier(zoneIds[getZoneName(record)]), record.ID)
			if err != nil {
				log.Fatal(err)
			}
		}

		for _, record := range adding {
			fmt.Printf("creating %-20s%-8s%-6d%-40s%s... ", getZoneName(record), record.Type, record.TTL, record.Name, record.Content)

			res, err := api.CreateDNSRecord(ctx, cloudflare.ZoneIdentifier(zoneIds[getZoneName(record)]), cloudflare.CreateDNSRecordParams{
				Type:     record.Type,
				Name:     record.Name,
				Content:  record.Content,
				TTL:      record.TTL,
				Priority: record.Priority,
				Proxied:  record.Proxied,
			})
			if err != nil {
				log.Fatal(err)
			}
			fmt.Printf("%v\n", *res.Proxied)
		}
	}
}

func hash(r cloudflare.DNSRecord) string {
	var s [16]byte

	if r.Type == "MX" {
		s = md5.Sum([]byte(fmt.Sprintf("%s-%s-%d-%s-%s-%d", getZoneName(r), r.Type, r.TTL, r.Name, r.Content, *r.Priority)))
	} else if r.Type == "A" || r.Type == "CNAME" || r.Type == "DEPRECATED" {
		s = md5.Sum([]byte(fmt.Sprintf("%s-%s-%d-%s-%s-%v", getZoneName(r), "X", r.TTL, r.Name, r.Content, *r.Proxied)))
	} else {
		s = md5.Sum([]byte(fmt.Sprintf("%s-%s-%d-%s-%s", getZoneName(r), r.Type, r.TTL, r.Name, r.Content)))
	}

	return hex.EncodeToString(s[:])
}

func nt(r cloudflare.DNSRecord) string {
	if r.Type == "A" || r.Type == "CNAME" || r.Type == "DEPRECATED" {
		return fmt.Sprintf("%s-X", r.Name)
	}
	return fmt.Sprintf("%s-%s", r.Name, r.Type)
}

type Set[T comparable] map[T]struct{}

func SetOf[T comparable]() Set[T] {
	return make(Set[T], 0)
}

func (s Set[T]) Add(item T) bool {
	if _, ok := s[item]; ok {
		return false
	}
	s[item] = struct{}{}
	return true
}

func (s Set[T]) Has(item T) bool {
	_, ok := s[item]
	return ok
}

func getZoneName(record cloudflare.DNSRecord) string {
	parts := strings.Split(record.Name, ".")
	if len(parts) < 2 {
		return record.Name
	}
	return strings.Join(parts[len(parts)-2:], ".")
}

func toInterfaceSlice(strs []string) []interface{} {
	interfaces := make([]interface{}, len(strs))
	for i, v := range strs {
		interfaces[i] = v
	}
	return interfaces
}

func usage() {
	fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
	fmt.Println("\nToken source options:")
	fmt.Println("  -token=env: Use CLOUDFLARE_API_TOKEN environment variable")
	fmt.Println("  -token=1password: Use 1Password Connect with:")
	fmt.Println("    - OP_SERVICE_ACCOUNT_TOKEN: 1Password Connect token")
	fmt.Println("    - CF_1PASSWORD_ITEM: Reference to the item containing the token")
	fmt.Println("  -token=vault: Use Hashicorp Vault with:")
	fmt.Println("    - VAULT_ADDR: Vault server URL (optional)")
	fmt.Println("    - VAULT_TOKEN: Vault authentication token")
	fmt.Println("    - CLOUDFLARE_VAULT_PATH: Path to the secret in Vault")
	fmt.Println("    - CLOUDFLARE_VAULT_KEY: Key for the token in the secret (defaults to 'token')")
	fmt.Println("\nFlags:")
	flag.PrintDefaults()
}
