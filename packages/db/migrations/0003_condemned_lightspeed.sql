CREATE TABLE `journal_drafts` (
	`id` text PRIMARY KEY NOT NULL,
	`user_id` text NOT NULL,
	`machine_identity_id` text,
	`title` text NOT NULL,
	`content` text NOT NULL,
	`tags` text,
	`created_at` integer NOT NULL,
	`updated_at` integer NOT NULL,
	FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`machine_identity_id`) REFERENCES `machine_identities`(`id`) ON UPDATE no action ON DELETE set null
);
--> statement-breakpoint
CREATE TABLE `engineering_progress` (
	`id` text PRIMARY KEY NOT NULL,
	`user_id` text NOT NULL,
	`machine_identity_id` text,
	`summary` text NOT NULL,
	`details` text,
	`blockers` text,
	`status` text DEFAULT 'in_progress' NOT NULL,
	`created_at` integer NOT NULL,
	`updated_at` integer NOT NULL,
	FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`machine_identity_id`) REFERENCES `machine_identities`(`id`) ON UPDATE no action ON DELETE set null
);
