#!/usr/bin/env python3
"""
Script CLI pour exécuter les attaques CORS sans interface web.
Utile pour les démonstrations en ligne de commande.

Usage:
    python run_attack_cli.py wildcard
    python run_attack_cli.py wildcard --secure
    python run_attack_cli.py reflection --target http://localhost:8000
"""

import asyncio
import sys
import argparse
import json
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from attacks.brute_force import BruteForceAttack
from attacks.reflection import ReflectionAttack
from attacks.null_origin import NullOriginAttack
from attacks.permissive import PermissiveAttack
from attacks.vary_attack import VaryAttack


# Mapping des noms d'attaques vers les classes
ATTACK_CLASSES = {
    "wildcard": BruteForceAttack,
    "reflection": ReflectionAttack,
    "null_origin": NullOriginAttack,
    "permissive": PermissiveAttack,
    "vary": VaryAttack
}


def print_banner():
    """Affiche une bannière de démarrage"""
    print("╔═══════════════════════════════════════════════════════════════╗")
    print("║     EXÉCUTION D'ATTAQUE CORS - MODE LIGNE DE COMMANDE        ║")
    print("╚═══════════════════════════════════════════════════════════════╝")
    print()


def print_result(result, test_secure: bool = False):
    """Affiche les résultats de l'attaque de manière formatée"""
    print("\n" + "="*70)
    print(f"RÉSULTATS DE L'ATTAQUE - {result.attack_type.upper()}")
    print("="*70)
    
    # Statut
    status_icon = "✓" if result.success else "✗"
    status_text = "SUCCÈS" if result.success else "BLOQUÉ"
    print(f"\n{status_icon} Statut: {status_text}")
    
    # Métriques
    print(f"⏱️  Durée: {result.duration_seconds:.2f} secondes")
    print(f"📤 Requêtes envoyées: {result.requests_sent}")
    
    # Endpoints
    if result.vulnerable_endpoints:
        print(f"\n🎯 Endpoints vulnérables:")
        for endpoint in result.vulnerable_endpoints:
            print(f"   - {endpoint}")
    
    # Données volées
    if result.stolen_data:
        print(f"\n{'🛡️  Résultat du Test' if test_secure else '🔓 Données Volées'}:")
        print(json.dumps(result.stolen_data, indent=2, ensure_ascii=False))
    
    # Détails des requêtes
    if result.request_details:
        print(f"\n📤 Détails des Requêtes:")
        for i, req in enumerate(result.request_details, 1):
            print(f"\n   Requête {i}:")
            print(f"   - Méthode: {req.get('method', 'GET')}")
            print(f"   - URL: {req.get('url', 'N/A')}")
            if 'description' in req:
                print(f"   - Description: {req['description']}")
    
    # Détails des réponses
    if result.response_details:
        print(f"\n📥 Détails des Réponses:")
        for i, resp in enumerate(result.response_details, 1):
            print(f"\n   Réponse {i}:")
            print(f"   - Endpoint: {resp.get('endpoint', 'N/A')}")
            print(f"   - Type: {resp.get('type', 'N/A')}")
            print(f"   - Statut: {resp.get('status', 'N/A')}")
            print(f"   - Résultat: {resp.get('result', 'N/A')}")
            
            if 'cors_headers' in resp:
                print(f"   - En-têtes CORS:")
                for key, value in resp['cors_headers'].items():
                    print(f"     • {key}: {value}")
    
    # Notes éducatives
    if result.educational_notes:
        print(f"\n📚 Notes Éducatives:")
        print("-" * 70)
        print(result.educational_notes)
        print("-" * 70)
    
    # Erreur
    if result.error:
        print(f"\n⚠️  Erreur: {result.error}")
    
    print("\n" + "="*70)


async def run_attack(attack_type: str, target_url: str, test_secure: bool = False):
    """
    Exécute une attaque spécifique
    
    Args:
        attack_type: Type d'attaque (wildcard, reflection, etc.)
        target_url: URL cible
        test_secure: Si True, teste uniquement l'endpoint sécurisé
    """
    # Vérifier que le type d'attaque est valide
    if attack_type not in ATTACK_CLASSES:
        print(f"❌ Erreur: Type d'attaque '{attack_type}' inconnu")
        print(f"Types disponibles: {', '.join(ATTACK_CLASSES.keys())}")
        return 1
    
    # Obtenir la classe d'attaque
    attack_class = ATTACK_CLASSES[attack_type]
    
    # Créer l'instance d'attaque
    print(f"🎯 Initialisation de l'attaque '{attack_type}'...")
    print(f"🌐 Cible: {target_url}")
    print(f"{'🛡️  Mode: Test de protection (endpoint sécurisé)' if test_secure else '⚠️  Mode: Exploitation (endpoint vulnérable)'}")
    print()
    
    try:
        # Créer l'instance avec les bons paramètres
        if attack_type == "wildcard":
            attack = attack_class(
                target_url=target_url,
                demo_mode=True,
                test_secure_only=test_secure
            )
        else:
            attack = attack_class(
                target_url=target_url,
                demo_mode=True
            )
        
        # Exécuter l'attaque
        print("⏳ Exécution de l'attaque en cours...")
        result = await attack.run()
        
        # Afficher les résultats
        print_result(result, test_secure)
        
        return 0
        
    except Exception as e:
        print(f"\n❌ Erreur lors de l'exécution: {e}")
        import traceback
        traceback.print_exc()
        return 1


def main():
    """Point d'entrée principal"""
    parser = argparse.ArgumentParser(
        description="Exécute une attaque CORS en ligne de commande",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples:
  # Attaquer l'endpoint vulnérable
  python run_attack_cli.py wildcard
  
  # Tester l'endpoint sécurisé
  python run_attack_cli.py wildcard --secure
  
  # Spécifier une cible différente
  python run_attack_cli.py reflection --target http://example.com:8000
  
  # Autres attaques disponibles
  python run_attack_cli.py null_origin
  python run_attack_cli.py permissive
  python run_attack_cli.py vary
        """
    )
    
    parser.add_argument(
        "attack_type",
        choices=list(ATTACK_CLASSES.keys()),
        help="Type d'attaque à exécuter"
    )
    
    parser.add_argument(
        "--target",
        "-t",
        default="http://localhost:8000",
        help="URL cible (défaut: http://localhost:8000)"
    )
    
    parser.add_argument(
        "--secure",
        "-s",
        action="store_true",
        help="Tester l'endpoint sécurisé au lieu du vulnérable"
    )
    
    parser.add_argument(
        "--json",
        "-j",
        action="store_true",
        help="Sortie en format JSON"
    )
    
    args = parser.parse_args()
    
    # Afficher la bannière
    if not args.json:
        print_banner()
    
    # Exécuter l'attaque
    exit_code = asyncio.run(run_attack(
        args.attack_type,
        args.target,
        args.secure
    ))
    
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
