#!/usr/bin/env python3
"""
Machine Learning Training System for Honeypot Intrusion Detection
Uses UNSW-NB15 dataset to train models for real-time attack detection
"""

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.model_selection import train_test_split, cross_val_score, GridSearchCV
from sklearn.preprocessing import LabelEncoder, StandardScaler, MinMaxScaler
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC
from sklearn.neural_network import MLPClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, roc_auc_score, roc_curve
from sklearn.feature_selection import SelectKBest, f_classif
import joblib
import warnings
import os
from datetime import datetime
import json

warnings.filterwarnings('ignore')

class HoneypotMLTrainer:
    def __init__(self, data_path="csv/CSV Files/Training and Testing Sets/"):
        self.data_path = data_path
        self.models = {}
        self.scalers = {}
        self.encoders = {}
        self.feature_selector = None
        self.best_model = None
        self.results = {}
        
        # Create output directories
        os.makedirs('ml_models', exist_ok=True)
        os.makedirs('ml_results', exist_ok=True)
        os.makedirs('ml_plots', exist_ok=True)
    
    def load_data(self):
        """Load and combine training and testing datasets"""
        print("📊 Loading UNSW-NB15 dataset...")
        
        try:
            # Load training data
            train_path = os.path.join(self.data_path, "UNSW_NB15_training-set.csv")
            test_path = os.path.join(self.data_path, "UNSW_NB15_testing-set.csv")
            
            print(f"   Loading training data: {train_path}")
            train_data = pd.read_csv(train_path)
            
            print(f"   Loading testing data: {test_path}")
            test_data = pd.read_csv(test_path)
            
            # Combine datasets
            self.data = pd.concat([train_data, test_data], ignore_index=True)
            
            print(f"✅ Dataset loaded successfully!")
            print(f"   Total samples: {len(self.data):,}")
            print(f"   Features: {len(self.data.columns)}")
            print(f"   Memory usage: {self.data.memory_usage(deep=True).sum() / 1024**2:.2f} MB")
            
            return True
            
        except Exception as e:
            print(f"❌ Error loading dataset: {e}")
            return False
    
    def explore_data(self):
        """Perform exploratory data analysis"""
        print("\n🔍 Performing Exploratory Data Analysis...")
        
        # Basic info
        print(f"Dataset shape: {self.data.shape}")
        print(f"Columns: {list(self.data.columns)}")
        
        # Check for missing values
        missing_values = self.data.isnull().sum()
        if missing_values.sum() > 0:
            print(f"Missing values found:")
            print(missing_values[missing_values > 0])
        else:
            print("✅ No missing values found")
        
        # Target distribution
        print(f"\nTarget distribution:")
        print(self.data['label'].value_counts())
        print(f"Attack categories:")
        print(self.data['attack_cat'].value_counts())
        
        # Save basic statistics
        stats = {
            'total_samples': int(len(self.data)),
            'total_features': int(len(self.data.columns)),
            'attack_samples': int(self.data['label'].sum()),
            'normal_samples': int(len(self.data) - self.data['label'].sum()),
            'attack_rate': float(self.data['label'].mean()),
            'attack_categories': {str(k): int(v) for k, v in self.data['attack_cat'].value_counts().to_dict().items()}
        }
        
        with open('ml_results/dataset_stats.json', 'w') as f:
            json.dump(stats, f, indent=2)
        
        return stats
    
    def preprocess_data(self):
        """Preprocess the data for machine learning"""
        print("\n🔧 Preprocessing data...")
        
        # Create a copy for preprocessing
        data_processed = self.data.copy()
        
        # Remove unnecessary columns
        columns_to_drop = ['id']  # Remove ID column
        data_processed = data_processed.drop(columns=columns_to_drop, errors='ignore')
        
        # Handle categorical variables
        categorical_columns = ['proto', 'service', 'state', 'attack_cat']
        
        for col in categorical_columns:
            if col in data_processed.columns:
                le = LabelEncoder()
                data_processed[col] = le.fit_transform(data_processed[col].astype(str))
                self.encoders[col] = le
        
        # Separate features and target
        self.target = data_processed['label']
        self.features = data_processed.drop(['label', 'attack_cat'], axis=1)
        
        print(f"✅ Preprocessing completed!")
        print(f"   Features shape: {self.features.shape}")
        print(f"   Target shape: {self.target.shape}")
        print(f"   Feature columns: {list(self.features.columns)}")
        
        return True
    
    def feature_engineering(self):
        """Perform feature engineering and selection"""
        print("\n⚙️ Performing feature engineering...")
        
        # Feature selection using SelectKBest
        k_best = 20  # Select top 20 features
        self.feature_selector = SelectKBest(score_func=f_classif, k=k_best)
        
        # Fit feature selector
        X_selected = self.feature_selector.fit_transform(self.features, self.target)
        
        # Get selected feature names
        selected_features = self.features.columns[self.feature_selector.get_support()].tolist()
        
        print(f"✅ Feature selection completed!")
        print(f"   Selected {len(selected_features)} features out of {len(self.features.columns)}")
        print(f"   Selected features: {selected_features}")
        
        # Update features
        self.features = pd.DataFrame(X_selected, columns=selected_features)
        
        # Save feature importance
        feature_scores = pd.DataFrame({
            'feature': self.features.columns,
            'score': self.feature_selector.scores_[self.feature_selector.get_support()]
        }).sort_values('score', ascending=False)
        
        feature_scores.to_csv('ml_results/feature_importance.csv', index=False)
        
        return True
    
    def split_data(self, test_size=0.2, random_state=42):
        """Split data into training and testing sets"""
        print(f"\n📊 Splitting data (test_size={test_size})...")
        
        self.X_train, self.X_test, self.y_train, self.y_test = train_test_split(
            self.features, self.target, test_size=test_size, random_state=random_state, stratify=self.target
        )
        
        print(f"✅ Data split completed!")
        print(f"   Training set: {self.X_train.shape}")
        print(f"   Testing set: {self.X_test.shape}")
        print(f"   Training labels: {self.y_train.value_counts().to_dict()}")
        print(f"   Testing labels: {self.y_test.value_counts().to_dict()}")
        
        return True
    
    def scale_features(self):
        """Scale features for better model performance"""
        print("\n📏 Scaling features...")
        
        # Use StandardScaler for most models
        self.scalers['standard'] = StandardScaler()
        self.X_train_scaled = self.scalers['standard'].fit_transform(self.X_train)
        self.X_test_scaled = self.scalers['standard'].transform(self.X_test)
        
        # Use MinMaxScaler for neural networks
        self.scalers['minmax'] = MinMaxScaler()
        self.X_train_minmax = self.scalers['minmax'].fit_transform(self.X_train)
        self.X_test_minmax = self.scalers['minmax'].transform(self.X_test)
        
        print("✅ Feature scaling completed!")
        
        return True
    
    def train_models(self):
        """Train multiple machine learning models"""
        print("\n🤖 Training machine learning models...")
        
        # Define models to train
        models_config = {
            'RandomForest': {
                'model': RandomForestClassifier(random_state=42, n_jobs=-1),
                'params': {
                    'n_estimators': [100, 200],
                    'max_depth': [10, 20, None],
                    'min_samples_split': [2, 5]
                },
                'use_scaled': False
            },
            'GradientBoosting': {
                'model': GradientBoostingClassifier(random_state=42),
                'params': {
                    'n_estimators': [100, 200],
                    'learning_rate': [0.1, 0.2],
                    'max_depth': [3, 5]
                },
                'use_scaled': False
            },
            'LogisticRegression': {
                'model': LogisticRegression(random_state=42, max_iter=1000),
                'params': {
                    'C': [0.1, 1, 10],
                    'penalty': ['l1', 'l2'],
                    'solver': ['liblinear']
                },
                'use_scaled': True
            },
            'SVM': {
                'model': SVC(random_state=42, probability=True),
                'params': {
                    'C': [0.1, 1, 10],
                    'kernel': ['rbf', 'linear'],
                    'gamma': ['scale', 'auto']
                },
                'use_scaled': True
            },
            'NeuralNetwork': {
                'model': MLPClassifier(random_state=42, max_iter=500),
                'params': {
                    'hidden_layer_sizes': [(50,), (100,), (50, 50)],
                    'activation': ['relu', 'tanh'],
                    'alpha': [0.0001, 0.001]
                },
                'use_scaled': True,
                'use_minmax': True
            }
        }
        
        # Train each model
        for name, config in models_config.items():
            print(f"\n   Training {name}...")
            
            try:
                # Select appropriate data
                if config.get('use_minmax', False):
                    X_train_data = self.X_train_minmax
                    X_test_data = self.X_test_minmax
                elif config.get('use_scaled', False):
                    X_train_data = self.X_train_scaled
                    X_test_data = self.X_test_scaled
                else:
                    X_train_data = self.X_train
                    X_test_data = self.X_test
                
                # Grid search for hyperparameter tuning
                grid_search = GridSearchCV(
                    config['model'], 
                    config['params'], 
                    cv=3, 
                    scoring='accuracy', 
                    n_jobs=-1,
                    verbose=0
                )
                
                # Fit the model
                grid_search.fit(X_train_data, self.y_train)
                
                # Store the best model
                self.models[name] = grid_search.best_estimator_
                
                # Make predictions
                y_pred = self.models[name].predict(X_test_data)
                y_pred_proba = self.models[name].predict_proba(X_test_data)[:, 1] if hasattr(self.models[name], 'predict_proba') else None
                
                # Calculate metrics
                accuracy = accuracy_score(self.y_test, y_pred)
                auc_score = roc_auc_score(self.y_test, y_pred_proba) if y_pred_proba is not None else None
                
                # Store results
                self.results[name] = {
                    'accuracy': accuracy,
                    'auc_score': auc_score,
                    'best_params': grid_search.best_params_,
                    'predictions': y_pred,
                    'probabilities': y_pred_proba
                }
                
                print(f"   ✅ {name} - Accuracy: {accuracy:.4f}, AUC: {auc_score:.4f if auc_score else 'N/A'}")
                
            except Exception as e:
                print(f"   ❌ Error training {name}: {e}")
        
        print(f"\n✅ Model training completed! Trained {len(self.models)} models.")
        
        return True
    
    def evaluate_models(self):
        """Evaluate and compare all trained models"""
        print("\n📊 Evaluating models...")
        
        # Create evaluation report
        evaluation_report = {}
        
        for name, results in self.results.items():
            print(f"\n   Evaluating {name}...")
            
            # Classification report
            report = classification_report(
                self.y_test, 
                results['predictions'], 
                target_names=['Normal', 'Attack'],
                output_dict=True
            )
            
            # Confusion matrix
            cm = confusion_matrix(self.y_test, results['predictions'])
            
            # Store evaluation results
            evaluation_report[name] = {
                'accuracy': results['accuracy'],
                'auc_score': results['auc_score'],
                'classification_report': report,
                'confusion_matrix': cm.tolist(),
                'best_params': results['best_params']
            }
            
            print(f"   Accuracy: {results['accuracy']:.4f}")
            print(f"   AUC Score: {results['auc_score']:.4f if results['auc_score'] else 'N/A'}")
        
        # Find best model
        best_model_name = max(self.results.keys(), key=lambda x: self.results[x]['accuracy'])
        self.best_model = self.models[best_model_name]
        
        print(f"\n🏆 Best model: {best_model_name} (Accuracy: {self.results[best_model_name]['accuracy']:.4f})")
        
        # Save evaluation report
        with open('ml_results/evaluation_report.json', 'w') as f:
            json.dump(evaluation_report, f, indent=2)
        
        return evaluation_report
    
    def create_visualizations(self):
        """Create visualizations for model evaluation"""
        print("\n📈 Creating visualizations...")
        
        # Set style
        plt.style.use('seaborn-v0_8')
        
        # 1. Model Comparison
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 6))
        
        models = list(self.results.keys())
        accuracies = [self.results[model]['accuracy'] for model in models]
        auc_scores = [self.results[model]['auc_score'] for model in models if self.results[model]['auc_score'] is not None]
        auc_models = [model for model in models if self.results[model]['auc_score'] is not None]
        
        # Accuracy comparison
        ax1.bar(models, accuracies, color='skyblue', alpha=0.7)
        ax1.set_title('Model Accuracy Comparison')
        ax1.set_ylabel('Accuracy')
        ax1.set_ylim(0, 1)
        ax1.tick_params(axis='x', rotation=45)
        
        # Add value labels on bars
        for i, v in enumerate(accuracies):
            ax1.text(i, v + 0.01, f'{v:.3f}', ha='center', va='bottom')
        
        # AUC comparison
        if auc_scores:
            ax2.bar(auc_models, auc_scores, color='lightcoral', alpha=0.7)
            ax2.set_title('Model AUC Score Comparison')
            ax2.set_ylabel('AUC Score')
            ax2.set_ylim(0, 1)
            ax2.tick_params(axis='x', rotation=45)
            
            # Add value labels on bars
            for i, v in enumerate(auc_scores):
                ax2.text(i, v + 0.01, f'{v:.3f}', ha='center', va='bottom')
        
        plt.tight_layout()
        plt.savefig('ml_plots/model_comparison.png', dpi=300, bbox_inches='tight')
        plt.close()
        
        # 2. Confusion Matrix for Best Model
        best_model_name = max(self.results.keys(), key=lambda x: self.results[x]['accuracy'])
        cm = confusion_matrix(self.y_test, self.results[best_model_name]['predictions'])
        
        plt.figure(figsize=(8, 6))
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', 
                   xticklabels=['Normal', 'Attack'], 
                   yticklabels=['Normal', 'Attack'])
        plt.title(f'Confusion Matrix - {best_model_name}')
        plt.ylabel('True Label')
        plt.xlabel('Predicted Label')
        plt.savefig('ml_plots/confusion_matrix.png', dpi=300, bbox_inches='tight')
        plt.close()
        
        # 3. ROC Curves
        plt.figure(figsize=(10, 8))
        
        for name, results in self.results.items():
            if results['probabilities'] is not None:
                fpr, tpr, _ = roc_curve(self.y_test, results['probabilities'])
                auc_score = results['auc_score']
                plt.plot(fpr, tpr, label=f'{name} (AUC = {auc_score:.3f})')
        
        plt.plot([0, 1], [0, 1], 'k--', label='Random Classifier')
        plt.xlabel('False Positive Rate')
        plt.ylabel('True Positive Rate')
        plt.title('ROC Curves Comparison')
        plt.legend()
        plt.grid(True, alpha=0.3)
        plt.savefig('ml_plots/roc_curves.png', dpi=300, bbox_inches='tight')
        plt.close()
        
        print("✅ Visualizations created and saved to ml_plots/")
        
        return True
    
    def save_models(self):
        """Save trained models and preprocessing objects"""
        print("\n💾 Saving models and preprocessing objects...")
        
        # Save models
        for name, model in self.models.items():
            model_path = f'ml_models/{name.lower()}_model.pkl'
            joblib.dump(model, model_path)
            print(f"   Saved {name} model to {model_path}")
        
        # Save scalers
        for name, scaler in self.scalers.items():
            scaler_path = f'ml_models/{name}_scaler.pkl'
            joblib.dump(scaler, scaler_path)
            print(f"   Saved {name} scaler to {scaler_path}")
        
        # Save encoders
        for name, encoder in self.encoders.items():
            encoder_path = f'ml_models/{name}_encoder.pkl'
            joblib.dump(encoder, encoder_path)
            print(f"   Saved {name} encoder to {encoder_path}")
        
        # Save feature selector
        if self.feature_selector:
            joblib.dump(self.feature_selector, 'ml_models/feature_selector.pkl')
            print("   Saved feature selector")
        
        # Save best model info
        best_model_name = max(self.results.keys(), key=lambda x: self.results[x]['accuracy'])
        best_model_info = {
            'name': best_model_name,
            'accuracy': self.results[best_model_name]['accuracy'],
            'auc_score': self.results[best_model_name]['auc_score'],
            'best_params': self.results[best_model_name]['best_params'],
            'feature_columns': list(self.features.columns),
            'training_date': datetime.now().isoformat()
        }
        
        with open('ml_models/best_model_info.json', 'w') as f:
            json.dump(best_model_info, f, indent=2)
        
        print(f"✅ All models and preprocessing objects saved!")
        print(f"🏆 Best model: {best_model_name}")
        
        return True
    
    def generate_report(self):
        """Generate a comprehensive training report"""
        print("\n📋 Generating training report...")
        
        report = f"""
# Machine Learning Training Report
Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Dataset Information
- **Dataset**: UNSW-NB15 Network Intrusion Detection
- **Total Samples**: {len(self.data):,}
- **Features**: {len(self.features.columns)}
- **Attack Rate**: {self.target.mean():.2%}

## Model Performance Summary
"""
        
        for name, results in self.results.items():
            report += f"""
### {name}
- **Accuracy**: {results['accuracy']:.4f}
- **AUC Score**: {results['auc_score']:.4f if results['auc_score'] else 'N/A'}
- **Best Parameters**: {results['best_params']}
"""
        
        best_model_name = max(self.results.keys(), key=lambda x: self.results[x]['accuracy'])
        report += f"""
## Best Model
**{best_model_name}** with accuracy of {self.results[best_model_name]['accuracy']:.4f}

## Files Generated
- Models: ml_models/
- Results: ml_results/
- Plots: ml_plots/
- Training Report: ml_results/training_report.md

## Next Steps
1. Deploy the best model for real-time intrusion detection
2. Integrate with honeypot system for automated threat detection
3. Set up monitoring and retraining pipeline
4. Implement model versioning and A/B testing
"""
        
        # Save report
        with open('ml_results/training_report.md', 'w') as f:
            f.write(report)
        
        print("✅ Training report generated: ml_results/training_report.md")
        
        return report
    
    def run_complete_training(self):
        """Run the complete machine learning training pipeline"""
        print("🚀 Starting Complete Machine Learning Training Pipeline")
        print("=" * 60)
        
        try:
            # Load data
            if not self.load_data():
                return False
            
            # Explore data
            self.explore_data()
            
            # Preprocess data
            if not self.preprocess_data():
                return False
            
            # Feature engineering
            if not self.feature_engineering():
                return False
            
            # Split data
            if not self.split_data():
                return False
            
            # Scale features
            if not self.scale_features():
                return False
            
            # Train models
            if not self.train_models():
                return False
            
            # Evaluate models
            self.evaluate_models()
            
            # Create visualizations
            self.create_visualizations()
            
            # Save models
            self.save_models()
            
            # Generate report
            self.generate_report()
            
            print("\n" + "=" * 60)
            print("🎉 Machine Learning Training Pipeline Completed Successfully!")
            print("=" * 60)
            
            return True
            
        except Exception as e:
            print(f"\n❌ Error in training pipeline: {e}")
            return False

def main():
    """Main entry point"""
    print("🤖 Honeypot Machine Learning Training System")
    print("Using UNSW-NB15 Dataset for Intrusion Detection")
    print("=" * 60)
    
    # Initialize trainer
    trainer = HoneypotMLTrainer()
    
    # Run complete training pipeline
    success = trainer.run_complete_training()
    
    if success:
        print("\n🎯 Training completed successfully!")
        print("📁 Check the following directories for results:")
        print("   - ml_models/ - Trained models and preprocessing objects")
        print("   - ml_results/ - Evaluation results and reports")
        print("   - ml_plots/ - Visualization plots")
        print("\n💡 Next: Integrate the best model with your honeypot system!")
    else:
        print("\n❌ Training failed. Please check the error messages above.")

if __name__ == "__main__":
    main()
