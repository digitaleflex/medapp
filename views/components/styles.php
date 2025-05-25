<?php
/**
 * Styles communs pour l'application MedConnect
 */
?>
<!-- Styles de base -->
<style>
    /* Variables CSS personnalisées */
    :root {
        --color-primary: #10B981;
        --color-primary-dark: #059669;
        --color-primary-light: #34D399;
        --color-secondary: #3B82F6;
        --color-secondary-dark: #2563EB;
        --color-secondary-light: #60A5FA;
        --color-danger: #EF4444;
        --color-warning: #F59E0B;
        --color-success: #10B981;
        --color-info: #3B82F6;
    }

    /* Styles de base */
    body {
        font-family: 'Poppins', sans-serif;
        background-color: #F3F4F6;
    }

    /* Composants réutilisables */
    .card {
        @apply bg-white rounded-xl shadow-sm p-6 transition-all duration-300;
    }

    .card:hover {
        @apply shadow-md transform -translate-y-1;
    }

    .btn {
        @apply px-4 py-2 rounded-lg font-medium transition-all duration-300;
    }

    .btn-primary {
        @apply bg-green-500 text-white hover:bg-green-600;
    }

    .btn-secondary {
        @apply bg-blue-500 text-white hover:bg-blue-600;
    }

    .btn-danger {
        @apply bg-red-500 text-white hover:bg-red-600;
    }

    .input-field {
        @apply w-full px-4 py-2 rounded-lg border border-gray-300 focus:ring-2 focus:ring-green-500 focus:border-green-500 transition-all duration-300;
    }

    .input-field:focus {
        @apply outline-none;
    }

    /* Effets de glassmorphisme */
    .glass {
        @apply bg-white bg-opacity-80 backdrop-filter backdrop-blur-lg;
    }

    /* Animations */
    .fade-in {
        animation: fadeIn 0.3s ease-in-out;
    }

    @keyframes fadeIn {
        from { opacity: 0; }
        to { opacity: 1; }
    }

    .slide-up {
        animation: slideUp 0.3s ease-in-out;
    }

    @keyframes slideUp {
        from { transform: translateY(20px); opacity: 0; }
        to { transform: translateY(0); opacity: 1; }
    }

    /* Styles spécifiques aux rôles */
    .role-medecin {
        --color-primary: #10B981;
        --color-primary-dark: #059669;
        --color-primary-light: #34D399;
    }

    .role-patient {
        --color-primary: #3B82F6;
        --color-primary-dark: #2563EB;
        --color-primary-light: #60A5FA;
    }

    /* Styles de navigation */
    .nav-link {
        @apply flex items-center px-4 py-2 rounded-lg transition-all duration-300;
    }

    .nav-link:hover {
        @apply bg-opacity-10;
    }

    .nav-link.active {
        @apply bg-opacity-20 font-medium;
    }

    /* Styles de tableau */
    .table-container {
        @apply overflow-x-auto rounded-lg shadow-sm;
    }

    .table {
        @apply min-w-full divide-y divide-gray-200;
    }

    .table th {
        @apply px-6 py-3 bg-gray-50 text-left text-xs font-medium text-gray-500 uppercase tracking-wider;
    }

    .table td {
        @apply px-6 py-4 whitespace-nowrap text-sm text-gray-900;
    }

    .table tr {
        @apply hover:bg-gray-50 transition-colors duration-200;
    }

    /* Styles de badge */
    .badge {
        @apply inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium;
    }

    .badge-success {
        @apply bg-green-100 text-green-800;
    }

    .badge-warning {
        @apply bg-yellow-100 text-yellow-800;
    }

    .badge-danger {
        @apply bg-red-100 text-red-800;
    }

    .badge-info {
        @apply bg-blue-100 text-blue-800;
    }

    /* Styles de formulaire */
    .form-group {
        @apply mb-4;
    }

    .form-label {
        @apply block text-sm font-medium text-gray-700 mb-1;
    }

    .form-error {
        @apply text-red-500 text-sm mt-1;
    }

    /* Styles de notification */
    .notification {
        @apply fixed top-4 right-4 p-4 rounded-lg shadow-lg z-50 fade-in;
    }

    .notification-success {
        @apply bg-green-500 text-white;
    }

    .notification-error {
        @apply bg-red-500 text-white;
    }

    .notification-warning {
        @apply bg-yellow-500 text-white;
    }

    .notification-info {
        @apply bg-blue-500 text-white;
    }
</style> 