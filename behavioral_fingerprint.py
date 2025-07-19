from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
import json

class BehavioralFingerprint:
    def __init__(self, known_apks_path="known_apks.json"):
        self.vectorizer = TfidfVectorizer(analyzer='word', ngram_range=(1, 2))
        self.known_prints = []
        self.known_labels = []
        self._load_known_apks(known_apks_path)

    def _load_known_apks(self, file_path):
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
                for item in data:
                    self.known_prints.append(self._features_to_string(item["features"]))
                    self.known_labels.append(item["label"])
            if self.known_prints:
                self.known_vectors = self.vectorizer.fit_transform(self.known_prints)
        except FileNotFoundError:
            # Handle case where the file doesn't exist yet
            pass

    def _features_to_string(self, features):
        # Convert the feature dictionary to a single string for vectorization
        return " ".join(features.get("permissions", [])) + " " + \
               " ".join(features.get("activities", [])) + " " + \
               " ".join(features.get("services", [])) + " " + \
               " ".join(features.get("receivers", []))

    def get_similarity(self, features):
        fingerprint_str = self._features_to_string(features)
        fingerprint_vector = self.vectorizer.transform([fingerprint_str])

        if not self.known_prints:
            return 0.0, "Unknown"

        similarities = cosine_similarity(fingerprint_vector, self.known_vectors)
        max_similarity_index = similarities.argmax()
        max_similarity = similarities[0, max_similarity_index]
        
        return max_similarity, self.known_labels[max_similarity_index]

# Initialize the fingerprint model
fingerprint_model = BehavioralFingerprint()
