CREATE TABLE `oauth_clients` (
	`id` text PRIMARY KEY NOT NULL,
	`client_name` text NOT NULL,
	`client_uri` text,
	`logo_uri` text,
	`redirect_uris` text NOT NULL,
	`grant_types` text DEFAULT '["authorization_code","refresh_token"]' NOT NULL,
	`response_types` text DEFAULT '["code"]' NOT NULL,
	`token_endpoint_auth_method` text DEFAULT 'none' NOT NULL,
	`created_at` integer NOT NULL
);
--> statement-breakpoint
CREATE TABLE `machine_identities` (
	`id` text PRIMARY KEY NOT NULL,
	`user_id` text NOT NULL,
	`client_id` text NOT NULL,
	`name` text NOT NULL,
	`scopes` text NOT NULL,
	`metadata` text,
	`last_used_at` integer,
	`last_ip_address` text,
	`revoked_at` integer,
	`revoked_reason` text,
	`created_at` integer NOT NULL,
	`updated_at` integer NOT NULL,
	FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`client_id`) REFERENCES `oauth_clients`(`id`) ON UPDATE no action ON DELETE no action
);
--> statement-breakpoint
CREATE TABLE `machine_tokens` (
	`id` text PRIMARY KEY NOT NULL,
	`machine_identity_id` text NOT NULL,
	`user_id` text NOT NULL,
	`client_id` text NOT NULL,
	`access_token_hash` text NOT NULL,
	`refresh_token_hash` text NOT NULL,
	`scopes` text NOT NULL,
	`resource` text,
	`access_token_expires_at` integer NOT NULL,
	`refresh_token_expires_at` integer NOT NULL,
	`revoked_at` integer,
	`created_at` integer NOT NULL,
	FOREIGN KEY (`machine_identity_id`) REFERENCES `machine_identities`(`id`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`client_id`) REFERENCES `oauth_clients`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE UNIQUE INDEX `machine_tokens_access_token_hash_unique` ON `machine_tokens` (`access_token_hash`);--> statement-breakpoint
CREATE UNIQUE INDEX `machine_tokens_refresh_token_hash_unique` ON `machine_tokens` (`refresh_token_hash`);--> statement-breakpoint
CREATE TABLE `oauth_auth_codes` (
	`code_hash` text PRIMARY KEY NOT NULL,
	`client_id` text NOT NULL,
	`user_id` text NOT NULL,
	`machine_identity_id` text NOT NULL,
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
CREATE TABLE `machine_audit_logs` (
	`id` text PRIMARY KEY NOT NULL,
	`machine_identity_id` text NOT NULL,
	`user_id` text NOT NULL,
	`request_id` text NOT NULL,
	`tool_name` text NOT NULL,
	`action_type` text NOT NULL,
	`scope_used` text,
	`resource_type` text,
	`resource_id` text,
	`input_payload` text NOT NULL,
	`output_payload` text,
	`before_state` text,
	`after_state` text,
	`reverse_action` text,
	`is_reversible` integer DEFAULT false NOT NULL,
	`status` text NOT NULL,
	`reverted_at` integer,
	`reverted_by_user_id` text,
	`revert_reason` text,
	`error_message` text,
	`ip_address` text,
	`user_agent` text,
	`duration_ms` integer NOT NULL,
	`created_at` integer NOT NULL,
	FOREIGN KEY (`machine_identity_id`) REFERENCES `machine_identities`(`id`) ON UPDATE no action ON DELETE restrict,
	FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON UPDATE no action ON DELETE cascade
);
