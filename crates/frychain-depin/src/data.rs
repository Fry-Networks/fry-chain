//! Data Marketplace for DePIN

use crate::did::DeviceDID;
use crate::{DePINError, DePINResult};
use frychain_core::address::Address;
use frychain_core::types::{Hash256, TokenAmount};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Data listing status
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ListingStatus {
    /// Listing is active and available
    Active,
    /// Listing is paused
    Paused,
    /// Listing has been sold/completed
    Completed,
    /// Listing has been cancelled
    Cancelled,
}

/// Data category
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DataCategory {
    /// Environmental data (temperature, humidity, etc.)
    Environmental,
    /// Location/GPS data
    Location,
    /// Industrial sensor data
    Industrial,
    /// Traffic/mobility data
    Traffic,
    /// Energy/power data
    Energy,
    /// Health/biometric data
    Health,
    /// Agricultural data
    Agricultural,
    /// Custom category
    Custom(String),
}

/// Data listing in the marketplace
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DataListing {
    /// Unique listing ID
    pub id: String,
    /// Device providing the data
    pub provider: DeviceDID,
    /// Owner address
    pub owner: Address,
    /// Data category
    pub category: DataCategory,
    /// Title/name
    pub title: String,
    /// Description
    pub description: String,
    /// Price per unit (in base tokens)
    pub price_per_unit: TokenAmount,
    /// Unit type (e.g., "hour", "record", "MB")
    pub unit_type: String,
    /// Available units (0 for unlimited)
    pub available_units: u64,
    /// Minimum purchase
    pub min_purchase: u64,
    /// Data schema (JSON schema)
    pub schema: serde_json::Value,
    /// Sample data hash
    pub sample_hash: Option<Hash256>,
    /// Listing status
    pub status: ListingStatus,
    /// Created timestamp
    pub created_at: u64,
    /// Updated timestamp
    pub updated_at: u64,
    /// Total sales
    pub total_sales: u64,
    /// Total revenue
    pub total_revenue: TokenAmount,
}

impl DataListing {
    /// Create a new data listing
    pub fn new(
        id: String,
        provider: DeviceDID,
        owner: Address,
        category: DataCategory,
        title: String,
        description: String,
        price_per_unit: TokenAmount,
        unit_type: String,
    ) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Self {
            id,
            provider,
            owner,
            category,
            title,
            description,
            price_per_unit,
            unit_type,
            available_units: 0,
            min_purchase: 1,
            schema: serde_json::Value::Null,
            sample_hash: None,
            status: ListingStatus::Active,
            created_at: now,
            updated_at: now,
            total_sales: 0,
            total_revenue: TokenAmount::ZERO,
        }
    }

    /// Set available units
    pub fn with_available_units(mut self, units: u64) -> Self {
        self.available_units = units;
        self
    }

    /// Set minimum purchase
    pub fn with_min_purchase(mut self, min: u64) -> Self {
        self.min_purchase = min;
        self
    }

    /// Set data schema
    pub fn with_schema(mut self, schema: serde_json::Value) -> Self {
        self.schema = schema;
        self
    }

    /// Calculate cost for units
    pub fn calculate_cost(&self, units: u64) -> TokenAmount {
        TokenAmount::new(self.price_per_unit.0 * units as u128)
    }

    /// Record a sale
    pub fn record_sale(&mut self, units: u64) {
        self.total_sales += units;
        self.total_revenue = TokenAmount::new(
            self.total_revenue.0 + self.price_per_unit.0 * units as u128,
        );

        if self.available_units > 0 {
            self.available_units = self.available_units.saturating_sub(units);
            if self.available_units == 0 {
                self.status = ListingStatus::Completed;
            }
        }

        self.updated_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
    }

    /// Pause the listing
    pub fn pause(&mut self) {
        self.status = ListingStatus::Paused;
        self.updated_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
    }

    /// Resume the listing
    pub fn resume(&mut self) {
        if self.status == ListingStatus::Paused {
            self.status = ListingStatus::Active;
            self.updated_at = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
        }
    }

    /// Cancel the listing
    pub fn cancel(&mut self) {
        self.status = ListingStatus::Cancelled;
        self.updated_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
    }
}

/// Data purchase record
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DataPurchase {
    /// Purchase ID
    pub id: String,
    /// Listing ID
    pub listing_id: String,
    /// Buyer address
    pub buyer: Address,
    /// Units purchased
    pub units: u64,
    /// Total price paid
    pub price_paid: TokenAmount,
    /// Purchase timestamp
    pub purchased_at: u64,
    /// Data delivery hash (for verification)
    pub delivery_hash: Option<Hash256>,
    /// Delivery status
    pub delivered: bool,
}

/// Data marketplace
#[derive(Clone, Debug, Default)]
pub struct DataMarketplace {
    /// Listings by ID
    listings: HashMap<String, DataListing>,
    /// Listings by category
    listings_by_category: HashMap<String, Vec<String>>,
    /// Listings by owner
    listings_by_owner: HashMap<Address, Vec<String>>,
    /// Purchases by buyer
    purchases_by_buyer: HashMap<Address, Vec<DataPurchase>>,
    /// Next listing ID
    next_id: u64,
}

impl DataMarketplace {
    /// Create a new data marketplace
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a new listing
    pub fn create_listing(&mut self, mut listing: DataListing) -> DePINResult<String> {
        let id = format!("listing-{}", self.next_id);
        self.next_id += 1;
        listing.id = id.clone();

        let category_key = format!("{:?}", listing.category);
        let owner = listing.owner;

        // Store listing
        self.listings.insert(id.clone(), listing);

        // Index by category
        self.listings_by_category
            .entry(category_key)
            .or_default()
            .push(id.clone());

        // Index by owner
        self.listings_by_owner
            .entry(owner)
            .or_default()
            .push(id.clone());

        Ok(id)
    }

    /// Get a listing by ID
    pub fn get_listing(&self, id: &str) -> Option<&DataListing> {
        self.listings.get(id)
    }

    /// Get a listing mutably
    pub fn get_listing_mut(&mut self, id: &str) -> Option<&mut DataListing> {
        self.listings.get_mut(id)
    }

    /// Get listings by category
    pub fn get_listings_by_category(&self, category: &DataCategory) -> Vec<&DataListing> {
        let category_key = format!("{:?}", category);
        self.listings_by_category
            .get(&category_key)
            .map(|ids| {
                ids.iter()
                    .filter_map(|id| self.listings.get(id))
                    .filter(|l| l.status == ListingStatus::Active)
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get listings by owner
    pub fn get_listings_by_owner(&self, owner: &Address) -> Vec<&DataListing> {
        self.listings_by_owner
            .get(owner)
            .map(|ids| ids.iter().filter_map(|id| self.listings.get(id)).collect())
            .unwrap_or_default()
    }

    /// Get all active listings
    pub fn get_active_listings(&self) -> Vec<&DataListing> {
        self.listings
            .values()
            .filter(|l| l.status == ListingStatus::Active)
            .collect()
    }

    /// Purchase data
    pub fn purchase(
        &mut self,
        listing_id: &str,
        buyer: Address,
        units: u64,
    ) -> DePINResult<DataPurchase> {
        let listing = self
            .listings
            .get_mut(listing_id)
            .ok_or_else(|| DePINError::InvalidDataListing("Listing not found".to_string()))?;

        // Validate
        if listing.status != ListingStatus::Active {
            return Err(DePINError::InvalidDataListing("Listing not active".to_string()));
        }

        if units < listing.min_purchase {
            return Err(DePINError::InvalidDataListing(format!(
                "Minimum purchase is {} units",
                listing.min_purchase
            )));
        }

        if listing.available_units > 0 && units > listing.available_units {
            return Err(DePINError::InvalidDataListing("Not enough units available".to_string()));
        }

        let price_paid = listing.calculate_cost(units);

        // Record sale
        listing.record_sale(units);

        // Create purchase record
        let purchase = DataPurchase {
            id: format!("purchase-{}", uuid::Uuid::new_v4()),
            listing_id: listing_id.to_string(),
            buyer,
            units,
            price_paid,
            purchased_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            delivery_hash: None,
            delivered: false,
        };

        // Store purchase
        self.purchases_by_buyer
            .entry(buyer)
            .or_default()
            .push(purchase.clone());

        Ok(purchase)
    }

    /// Get purchases by buyer
    pub fn get_purchases(&self, buyer: &Address) -> Vec<&DataPurchase> {
        self.purchases_by_buyer
            .get(buyer)
            .map(|purchases| purchases.iter().collect())
            .unwrap_or_default()
    }

    /// Get listing count
    pub fn listing_count(&self) -> usize {
        self.listings.len()
    }

    /// Get total volume
    pub fn total_volume(&self) -> TokenAmount {
        TokenAmount::new(
            self.listings
                .values()
                .map(|l| l.total_revenue.0)
                .sum(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_listing() -> DataListing {
        let address = Address::device_address(&[1u8; 32], b"sensor-001");
        let did = DeviceDID::new(address);
        let owner = Address::from_public_key(&[2u8; 64]);

        DataListing::new(
            "".to_string(),
            did,
            owner,
            DataCategory::Environmental,
            "Temperature Data".to_string(),
            "Hourly temperature readings".to_string(),
            TokenAmount::from_fry(1),
            "hour".to_string(),
        )
        .with_available_units(100)
    }

    #[test]
    fn test_create_listing() {
        let mut marketplace = DataMarketplace::new();
        let listing = create_listing();
        let owner = listing.owner;

        let id = marketplace.create_listing(listing).unwrap();
        assert!(marketplace.get_listing(&id).is_some());
        assert_eq!(marketplace.get_listings_by_owner(&owner).len(), 1);
    }

    #[test]
    fn test_purchase() {
        let mut marketplace = DataMarketplace::new();
        let listing = create_listing();
        let buyer = Address::from_public_key(&[3u8; 64]);

        let id = marketplace.create_listing(listing).unwrap();
        let purchase = marketplace.purchase(&id, buyer, 10).unwrap();

        assert_eq!(purchase.units, 10);
        assert_eq!(marketplace.get_listing(&id).unwrap().total_sales, 10);
    }

    #[test]
    fn test_purchase_min_check() {
        let mut marketplace = DataMarketplace::new();
        let mut listing = create_listing();
        listing.min_purchase = 5;
        let buyer = Address::from_public_key(&[3u8; 64]);

        let id = marketplace.create_listing(listing).unwrap();

        // Should fail - below minimum
        assert!(marketplace.purchase(&id, buyer, 2).is_err());

        // Should succeed - meets minimum
        assert!(marketplace.purchase(&id, buyer, 5).is_ok());
    }
}
