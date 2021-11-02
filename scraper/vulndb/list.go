package vulndb

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"nanscraper/common"
)

type ListVendorsResults struct {
	Vendors []ListVendorsVendorItem
	Aliases []ListVendorsAliasItem
}

type ListVendorsVendorItem struct {
	VendorId   int64  `xorm:"vendor_id"`
	VendorName string `xorm:"vendor_name"`
}

type ListVendorsAliasItem struct {
	VendorId    int64  `xorm:"vendor_id"`
	VendorName  string `xorm:"vendor_name"`
	VendorAlias string `xorm:"vendor_alias"`
}

// ListVendors looks up vendors from vendor inventory and aliases by `name`.
func ListVendors(session *VulnDBSession, name string) (*ListVendorsResults, error) {
	ret := ListVendorsResults{}

	// Vendors.
	sql := `
SELECT
vv.id AS vendor_id,
vv.name AS vendor_name
FROM vulndb_vendors vv
WHERE 1
`
	var params []interface{}
	if len(name) > 0 {
		sql += ` AND LOWER(vv.name) LIKE ?`
		params = append(params, strings.ToLower(name))
	}
	err := session.Sql(sql, params...).Find(&ret.Vendors)
	if err != nil {
		return nil, err
	}

	// Vendor aliases.
	sql = `
SELECT
vv.id AS vendor_id,
vv.name AS vendor_name,
vva.alias AS vendor_alias
FROM vulndb_vendor_aliases vva
INNER JOIN vulndb_vendors vv
ON vv.id = vva.vendor_id
WHERE 1
`
	params = []interface{}{}
	if len(name) > 0 {
		sql += ` AND LOWER(vva.alias) LIKE ?`
		params = append(params, strings.ToLower(name))
	}
	if len(ret.Vendors) > 0 && len(ret.Vendors) < 50 {
		sql += " OR " + common.MakeInSql("vendor_id", len(ret.Vendors))

		for _, v := range ret.Vendors {
			params = append(params, v.VendorId)
		}
	}
	err = session.Sql(sql, params...).Find(&ret.Aliases)
	if err != nil {
		return nil, err
	}

	return &ret, err
}

type ListProductsResults struct {
	AliasMatch       bool   // true if matched on a product alias.
	CPEFriendlyMatch bool   // true if matched via CPE friendly name.
	CPEFriendlyName  string // Set if matched via CPE friendly name.
	Products         []ListProductsProductItem
	Aliases          []ListProductsAliasItem
	VendorAliases    []string
}

type ListProductsProductItem struct {
	VendorName  string `xorm:"vendor_name"`
	ProductName string `xorm:"product_name"`
	ProductId   int64  `xorm:"product_id"`
}

type ListProductsAliasItem struct {
	ProductName  string `xorm:"product_name"`
	ProductId    int64  `xorm:"product_id"`
	VendorName   string `xorm:"vendor_name"`
	VendorAlias  string `xorm:"vendor_alias"`
	ProductAlias string `xorm:"product_alias"`
}

// ListProducts looks up products from product inventory and aliases by `name`.
// If `vendors` is specified then will limit the products returned to any of the vendors specified.
// If name is empty, will search all products.
func ListProducts(session *VulnDBSession, name string, vendorIds []int64) (*ListProductsResults, error) {
	ret := ListProductsResults{}

	sql := `
SELECT
vp.product_name AS product_name,
vp.id AS product_id,
vv.name AS vendor_name
FROM vulndb_products vp
INNER JOIN vulndb_vendors vv
ON vv.id = vp.vendor_id
WHERE 1
`
	var params []interface{}
	if len(name) > 0 {
		sql += ` AND LOWER(product_name) LIKE ?`
		params = append(params, strings.ToLower(name))
	}
	if len(vendorIds) > 0 {
		sql += " AND " + common.MakeInSql("vendor_id", len(vendorIds))
		for _, vid := range vendorIds {
			params = append(params, vid)
		}
	}
	err := session.Sql(sql, params...).Find(&ret.Products)
	if err != nil {
		return nil, err
	}

	// Product aliases.
	sql = `
SELECT
vp.id AS product_id,
vp.product_name AS product_name,
vv.name AS vendor_name,
vpa.product_alias AS product_alias,
vpa.vendor_alias AS vendor_alias
FROM vulndb_product_aliases vpa
INNER JOIN vulndb_products vp
ON vp.id = vpa.product_id
INNER JOIN vulndb_vendors vv
ON vv.id = vp.vendor_id
WHERE 1
`
	params = []interface{}{}
	if len(name) > 0 {
		sql += ` AND LOWER(vpa.product_alias) LIKE ?`
		params = append(params, strings.ToLower(name))
	}
	if len(vendorIds) > 0 {
		sql += ` AND ` + common.MakeInSql("vv.id", len(vendorIds))
		for _, vid := range vendorIds {
			params = append(params, vid)
		}
	}
	err = session.Sql(sql, params...).Find(&ret.Aliases)
	if err != nil {
		return nil, err
	}

	return &ret, nil
}

type ListProductItemsResults struct {
	Items []ListProductItemsProductItem
}

type ListProductItemsProductItem struct {
	VendorId              int64   `xorm:"vendor_id"`
	VendorName            string  `xorm:"vendor_name"`
	ProductId             int64   `xorm:"product_id"`
	ProductName           string  `xorm:"product_name"`
	ProductItemId         int64   `xorm:"product_item_id"`
	Systype               string  `xorm:"systype"`
	Version               *string `xorm:"version"`
	VersionStartExcluding *string `xorm:"version_start_excluding"`
	VersionStartIncluding *string `xorm:"version_start_including"`
	VersionEndExcluding   *string `xorm:"version_end_excluding"`
	VersionEndIncluding   *string `xorm:"version_end_including"`
	Patch                 string  `xorm:"patch"`
	CPE                   string  `xorm:"-"`
}

// ListProductItems looks up products items from product inventory by `vendor` and product `name`.
// If vendors is specified (not nil) then will limit the products returned to any of the vendors specified.
func ListProductItems(session *VulnDBSession, name string, vendorIds []int64) (*ListProductItemsResults, error) {
	ret := ListProductItemsResults{}

	var productIDs []int64
	prodlist, err := ListProducts(session, name, vendorIds)
	if err != nil {
		return nil, err
	}

	for _, prod := range prodlist.Products {
		productIDs = append(productIDs, prod.ProductId)
	}
	for _, pa := range prodlist.Aliases {
		productIDs = append(productIDs, pa.ProductId)
	}

	sql := `
SELECT
vv.id AS vendor_id,
vv.name AS vendor_name,
vp.id AS product_id,
vp.product_name AS product_name,
vpi.id AS product_item_id,
vpi.systype AS systype,
vpi.version AS version,
vpi.version_start_excluding AS version_start_excluding,
vpi.version_start_including AS version_start_including,
vpi.version_end_excluding AS version_end_excluding,
vpi.version_end_including AS version_end_including,
vpi.patch AS patch
FROM vulndb_product_items vpi
INNER JOIN vulndb_products vp
ON vp.id = vpi.product_id
INNER JOIN vulndb_vendors vv
ON vv.id = vp.vendor_id
WHERE 1
`
	sql += " AND " + common.MakeInSql("vp.id", len(productIDs))
	var params []interface{}
	for _, id := range productIDs {
		params = append(params, id)
	}

	err = session.Sql(sql, params...).Find(&ret.Items)
	if err != nil {
		return nil, err
	}

	// Populate CPE.
	for i, item := range ret.Items {
		var version string

		if item.Version != nil && *item.Version != "*" {
			version = *item.Version
		} else {
			if item.VersionStartIncluding != nil {
				version = fmt.Sprintf("[%s, ", *item.VersionStartIncluding)
			} else if item.VersionStartExcluding != nil {
				version = fmt.Sprintf("(%s, ", *item.VersionStartExcluding)
			} else {
				version = fmt.Sprintf("(, ")
			}
			if item.VersionEndIncluding != nil {
				version += fmt.Sprintf("%s]", *item.VersionEndIncluding)
			} else if item.VersionEndExcluding != nil {
				version += fmt.Sprintf("%s)", *item.VersionEndExcluding)
			} else {
				version += ")"
			}
		}

		cpe := "cpe:/" + item.Systype + ":" + item.VendorName + ":" + item.ProductName + ":" + version + ":" + item.Patch

		ret.Items[i].CPE = cpe
	}

	return &ret, nil
}

// ListProductsByCpe looks for products based on `cpe` (ignoring version).
// 1. Break cpe into (systype, vendor, product).
// 2. Look up vendor/product directly by vendor/product aliases and populate productIDs with match (and return vars).
// 3. If no matches. Look up vendor (both directly, checking vendor aliases, and potential cpe-friendly fits).
// 3b. If no vendor match - return nil.
// 4. If vendor match, look for matching product under vendor name, and populate the product ids into productIDs.
// 4b. If no product ID matches, return nil.
// 4. For each productID check all the product items for matching version.
// 5. Return a list of matching aliases and products.
func ListProductsByCpe(session *VulnDBSession, cpe string) (*ListProductsResults, error) {
	var ret ListProductsResults
	var productIDs []int64
	vendorIDMap := map[int64]bool{}

	// Step 1.
	cpeParts, err := ParseCPE(cpe)
	if err != nil {
		log.Debugf("CPE Parse error: %v", err)
		return nil, err
	}
	vendor, product := cpeParts.Vendor, cpeParts.Product

	// Step 2.
	var prodalias vulndbProductAlias
	has, err := session.Where("vendor_alias = ? AND ? GLOB product_alias", vendor, product).Get(&prodalias)
	if err != nil {
		return nil, err
	}
	if has {
		productIDs = append(productIDs, prodalias.ProductID)

		// Populate return variables with alias.
		var prod vulndbProduct
		has, err := session.Where(`id = ?`, prodalias.ProductID).Get(&prod)
		if err != nil {
			return nil, err
		}
		if !has {
			log.Debugf("ERROR: Product alias referring to nonexistent product id (%d)", prodalias.ProductID)
			return nil, errors.New("invalid product id")
		}

		var vend VulndbVendor
		has, err = session.Where(`id = ?`, prod.VendorID).Get(&vend)
		if err != nil {
			return nil, err
		}
		if !has {
			log.Debugf("ERROR: Product referring to nonexistent vendor id (%d)", prod.VendorID)
			return nil, errors.New("invalid vendor id")
		}

		alias := ListProductsAliasItem{
			ProductName:  prod.ProductName,
			ProductId:    prod.ID,
			VendorName:   vend.Name,
			VendorAlias:  prodalias.VendorAlias,
			ProductAlias: prodalias.ProductAlias,
		}
		ret.Aliases = append(ret.Aliases, alias)
		vendorIDMap[vend.ID] = true
	}

	if len(productIDs) == 0 {
		// Step 3.
		vendor, err := GetVendor(session, vendor)
		if err != nil {
			log.Debugf("ERROR getting vendor: %v", err)
			return nil, err
		}
		if vendor == nil {
			// Step 3b.
			return nil, err
		}
		vendorIDMap[vendor.ID] = true

		// Step 4.
		candidates := []string{product}
		whereSQL := "vendor_id = ? AND " + common.MakeInSql("product_name", len(candidates))
		params := []interface{}{vendor.ID}
		for _, candidate := range candidates {
			params = append(params, candidate)
		}
		var products []vulndbProduct
		err = session.Where(whereSQL, params...).Find(&products)
		if err != nil {
			return nil, err
		}
		for _, product := range products {
			productIDs = append(productIDs, product.ID)
			vendorIDMap[product.VendorID] = true
		}
	}

	// Step 4b.
	if len(productIDs) == 0 {
		return nil, nil
	}

	// Step 5.
	// Prepare output product list.
	{
		sql := `
SELECT
vp.product_name AS product_name,
vp.id AS product_id,
vv.name AS vendor_name
FROM vulndb_products vp
INNER JOIN vulndb_vendors vv
ON vv.id = vp.vendor_id
WHERE ` + common.MakeInSql("vp.id", len(productIDs))
		var params []interface{}
		for _, productID := range productIDs {
			params = append(params, productID)
		}

		err = session.Sql(sql, params...).Find(&ret.Products)
		if err != nil {
			return nil, err
		}
	}

	// Populate product aliases.
	if len(productIDs) > 0 {
		sql := `
SELECT
vpa.*
FROM
vulndb_product_aliases vpa
WHERE ` + common.MakeInSql(`vpa.product_id`, len(productIDs))
		var productAliases []vulndbProductAlias
		var params []interface{}
		for _, pid := range productIDs {
			params = append(params, pid)
		}
		err := session.Sql(sql, params...).Find(&productAliases)
		if err != nil {
			return nil, err
		}

		for _, palias := range productAliases {
			alias := ListProductsAliasItem{
				VendorAlias:  palias.VendorAlias,
				ProductAlias: palias.ProductAlias,
			}
			ret.Aliases = append(ret.Aliases, alias)
		}
	}

	// Populate vendor aliases.
	if len(vendorIDMap) > 0 {
		var vendorIDs []int64
		for vid, _ := range vendorIDMap {
			vendorIDs = append(vendorIDs, vid)
		}
		sort.Slice(vendorIDs, func(i, j int) bool {
			return vendorIDs[i] < vendorIDs[j]
		})

		var vendorAliases []VulndbVendorAlias
		sql := `
SELECT
vva.*
FROM 
vulndb_vendor_aliases vva
WHERE ` + common.MakeInSql("vva.vendor_id", len(vendorIDMap))
		var params []interface{}
		for _, vid := range vendorIDs {
			params = append(params, vid)
		}

		err := session.Sql(sql, params...).Find(&vendorAliases)
		if err != nil {
			return nil, err
		}

		for _, valias := range vendorAliases {
			ret.VendorAliases = append(ret.VendorAliases, valias.Alias)
		}
	}

	return &ret, nil
}

// ListProductsByTitles lists products by display names (title strings). Same approach as MatchCVEs uses.
// 1. Look up vendor/product directly by vendor/product aliases and populate productIDs with match.
// 2. If no matches. Look up vendor (both directly, checking vendor aliases, and potential cpe-friendly fits).
// 2b. If no vendor match - return nil.
// 3. If vendor match, look for matching product under vendor name, and populate the product ids into productIDs.
// 3b. If no product ID matches, return nil.
// 4. Populate return data with all matching product items.
func ListProductByTitles(session *VulnDBSession, publisher, title string) (*ListProductsResults, error) {
	var ret ListProductsResults
	var productIDs []int64

	// Step 1.
	var prodalias vulndbProductAlias
	has, err := session.Where("vendor_alias = ? AND ? GLOB product_alias", publisher, title).Get(&prodalias)
	if err != nil {
		return nil, err
	}
	if has {
		ret.AliasMatch = true
		productIDs = append(productIDs, prodalias.ProductID)
	}

	if len(productIDs) == 0 {
		// Step 2.
		vendor, err := GetVendor(session, publisher)
		if err != nil {
			log.Debugf("ERROR getting vendor: %v", err)
			return nil, err
		}
		if vendor == nil {
			// Step 2b.
			return nil, err
		}

		// Step 3.
		// Try both title directly, and prepared cpe-friendly product name.
		cpeFriendly := prepProductName(title, vendor.Name)

		candidates := []string{title}
		candidates = append(candidates, alternativeNames(cpeFriendly)...)
		var products []vulndbProduct

		whereSQL := "vendor_id = ? AND " + common.MakeInSql("product_name", len(candidates))
		params := []interface{}{vendor.ID}
		for _, candidate := range candidates {
			params = append(params, candidate)
		}
		err = session.Where(whereSQL, params...).Find(&products)
		if err != nil {
			return nil, err
		}
		for _, product := range products {
			if product.ProductName == cpeFriendly {
				ret.CPEFriendlyMatch = true
				ret.CPEFriendlyName = cpeFriendly
			}
			productIDs = append(productIDs, product.ID)
		}
	}

	// Step 3b.
	if len(productIDs) == 0 {
		return nil, nil
	}

	// Step 4.
	// Populate the return items.
	{
		// Populate products.
		sql := `
SELECT
vv.name AS vendor_name,
vp.id AS product_id,
vp.product_name AS product_name
FROM vulndb_products vp
INNER JOIN vulndb_vendors vv
ON vv.id = vp.vendor_id
WHERE 1
`
		sql += " AND " + common.MakeInSql("vp.id", len(productIDs))
		var params []interface{}
		for _, id := range productIDs {
			params = append(params, id)
		}
		err = session.Sql(sql, params...).Find(&ret.Products)
		if err != nil {
			return nil, err
		}
	}
	{
		// Populate product aliases.
		sql := `
SELECT
vpa.product_id AS product_id,
vpa.product_alias AS product_alias,
vpa.vendor_alias AS vendor_alias,
vv.name AS vendor_name,
vp.product_name AS product_name
FROM vulndb_product_aliases vpa
INNER JOIN vulndb_products vp
        ON vp.id = vpa.product_id
INNER JOIN vulndb_vendors vv
        ON vv.id = vp.vendor_id
`
		sql += `WHERE ` + common.MakeInSql(`vpa.product_id`, len(productIDs))
		var params []interface{}
		for _, id := range productIDs {
			params = append(params, id)
		}
		err = session.Sql(sql, params...).Find(&ret.Aliases)
		if err != nil {
			return nil, err
		}
	}
	{
		// Populate vendor aliases.
		sqlf := `
SELECT
vv.id AS vendor_id,
vv.name AS vendor_name,
vva.alias AS vendor_alias
FROM vulndb_vendor_aliases vva
INNER JOIN vulndb_vendors vv
        ON vv.id = vva.vendor_id
INNER JOIN vulndb_products vp
        ON vp.vendor_id = vv.id
WHERE %s
GROUP BY vv.id, vv.name, vva.alias
`
		whereSQL := common.MakeInSql(`vp.id`, len(productIDs))
		sql := fmt.Sprintf(sqlf, whereSQL)
		var params []interface{}
		for _, id := range productIDs {
			params = append(params, id)
		}
		var vendorAliases []struct {
			VendorID    int64  `xorm:"vendor_id"`
			VendorName  string `xorm:"vendor_name"`
			VendorAlias string `xorm:"vendor_alias"`
		}
		err := session.Sql(sql, params...).Find(&vendorAliases)
		if err != nil {
			return nil, err
		}
		for _, va := range vendorAliases {
			ret.VendorAliases = append(ret.VendorAliases, va.VendorAlias)
		}
	}

	return &ret, nil
}
