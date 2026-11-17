PRAGMA foreign_keys=OFF;--> statement-breakpoint
CREATE TABLE `__new_oauth_auth_codes` (
	`code_hash` text PRIMARY KEY NOT NULL,
	`client_id` text NOT NULL,
	`user_id` text NOT NULL,
	`machine_identity_id` text,
	`identity_name` text,
	`redirect_uri` text NOT NULL,
	`scopes` text NOT NULL,
	`code_challenge` text NOT NULL,
	`code_challenge_method` text DEFAULT 'S256' NOT NULL,
	`resource` text,
	`expires_at` integer NOT NULL,
	`used_at` integer,
	`created_at` integer NOT NULL,
	FOREIGN KEY (`client_id`) REFERENCES `oauth_clients`(`id`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`machine_identity_id`) REFERENCES `machine_identities`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
INSERT INTO `__new_oauth_auth_codes`("code_hash", "client_id", "user_id", "machine_identity_id", "identity_name", "redirect_uri", "scopes", "code_challenge", "code_challenge_method", "resource", "expires_at", "used_at", "created_at") SELECT "code_hash", "client_id", "user_id", "machine_identity_id", NULL, "redirect_uri", "scopes", "code_challenge", "code_challenge_method", "resource", "expires_at", "used_at", "created_at" FROM `oauth_auth_codes`;--> statement-breakpoint
DROP TABLE `oauth_auth_codes`;--> statement-breakpoint
ALTER TABLE `__new_oauth_auth_codes` RENAME TO `oauth_auth_codes`;--> statement-breakpoint
PRAGMA foreign_keys=ON;